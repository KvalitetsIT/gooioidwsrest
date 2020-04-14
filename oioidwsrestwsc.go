package oioidwsrest

import (
	"bytes"
	"fmt"
	"net/http"

	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"

	"encoding/base64"
	"encoding/pem"

	"time"
	"io/ioutil"

	securityprotocol "github.com/KvalitetsIT/gosecurityprotocol"
	stsclient "github.com/KvalitetsIT/gostsclient"

	"go.uber.org/zap"
)

const HTTP_HEADER_X_CLAIMS = "X-Claims"

type OioIdwsRestAuthenticationInfo struct {
	Token     string
	ExpiresIn int64
}

type OioIdwsRestHttpProtocolClientConfig struct {
	matchHandler securityprotocol.MatchHandler

	SessionHeaderName string

	StsUrl         string
	TrustCertFiles []string

	ClientCertFile string
	ClientKeyFile  string

	ServiceAudience string
	ServiceEndpoint string

	SessionDataFetcher securityprotocol.SessionDataFetcher

	Service securityprotocol.HttpHandler
}

type OioIdwsRestClientAuthentification func(http.ResponseWriter, *http.Request, *securityprotocol.SessionData) (*OioIdwsRestAuthenticationInfo, int, error)

type OioIdwsRestDecorateRequestWithAuthenticationToken func(tokenData *securityprotocol.TokenData, r *http.Request) error

type OioIdwsRestHttpProtocolClient struct {
	matchHandler securityprotocol.MatchHandler

	tokenCache securityprotocol.TokenCache

	sessionIdHandler   securityprotocol.SessionIdHandler
	sessionDataFetcher securityprotocol.SessionDataFetcher

	stsClient  *stsclient.StsClient
	httpClient *http.Client

	decorateRequest OioIdwsRestDecorateRequestWithAuthenticationToken

	serviceEndpoint string
	serviceAudience string

	service securityprotocol.HttpHandler

	Logger *zap.SugaredLogger
}

func CreateCaCertPool(trustCertFiles []string) *x509.CertPool {

	caCertPool, err := x509.SystemCertPool()
	if err != nil {
		panic(err)
	}
	for _, trustCertFile := range trustCertFiles {
		trustCert, err := ioutil.ReadFile(trustCertFile)
		if err != nil {
			panic(err)
		}
		trustBlock, _ := pem.Decode([]byte(trustCert))
		if err != nil {
			panic(err)
		}
		certToTrust, err := x509.ParseCertificate(trustBlock.Bytes)
		if err != nil {
			panic(err)
		}
		caCertPool.AddCert(certToTrust)
	}
	return caCertPool
}

func NewOioIdwsRestHttpProtocolClient(config OioIdwsRestHttpProtocolClientConfig, tokenCache securityprotocol.TokenCache, logger *zap.SugaredLogger) *OioIdwsRestHttpProtocolClient {

	// Truststore
	caCertPool := CreateCaCertPool(config.TrustCertFiles)

	// Clientkey
	clientKeyPair, err := tls.LoadX509KeyPair(config.ClientCertFile, config.ClientKeyFile)
	if err != nil {
		panic(err)
	}

	// Build the https client
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientKeyPair},
		RootCAs:      caCertPool,
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}

	// Public key
	certFileContent, err := ioutil.ReadFile(config.ClientCertFile)
	if err != nil {
		panic(err)
	}
	certBlock, _ := pem.Decode([]byte(certFileContent))
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		panic(err)
	}
	rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)

	// STSClient
	stsClient, err := stsclient.NewStsClientWithHttpClient(client, &clientKeyPair, rsaPublicKey, config.StsUrl)
	if err != nil {
		panic(err)
	}

	// Session handling
	sessionIdHandler := securityprotocol.HttpHeaderSessionIdHandler{HttpHeaderName: config.SessionHeaderName}

	return newOioIdwsRestHttpProtocolClient(config.matchHandler, tokenCache, sessionIdHandler, config.SessionDataFetcher, stsClient, client, config.ServiceEndpoint, config.ServiceAudience, config.Service, logger)
}

func newOioIdwsRestHttpProtocolClient(matchHandler securityprotocol.MatchHandler, tokenCache securityprotocol.TokenCache, sessionIdHandler securityprotocol.SessionIdHandler, sessionDataFetcher securityprotocol.SessionDataFetcher, stsClient *stsclient.StsClient, httpClient *http.Client, serviceEndpoint string, serviceAudience string, service securityprotocol.HttpHandler, logger *zap.SugaredLogger) *OioIdwsRestHttpProtocolClient {

	httpProtocolClient := new(OioIdwsRestHttpProtocolClient)
	httpProtocolClient.matchHandler = matchHandler
	httpProtocolClient.tokenCache = tokenCache
	httpProtocolClient.sessionIdHandler = sessionIdHandler
	httpProtocolClient.sessionDataFetcher = sessionDataFetcher
	httpProtocolClient.stsClient = stsClient
	httpProtocolClient.httpClient = httpClient
	httpProtocolClient.serviceEndpoint = serviceEndpoint
	httpProtocolClient.serviceAudience = serviceAudience
	httpProtocolClient.service = service
	httpProtocolClient.Logger = logger
	return httpProtocolClient
}

func (client OioIdwsRestHttpProtocolClient) Handle(w http.ResponseWriter, r *http.Request) (int, error) {
	return client.HandleService(w, r, client.service)
}

func (client OioIdwsRestHttpProtocolClient) HandleService(w http.ResponseWriter, r *http.Request, service securityprotocol.HttpHandler) (int, error) {

	returnCode, err, _ := client.HandleServiceWithCallback(w, r, service)
	return returnCode, err

}

func (client OioIdwsRestHttpProtocolClient) HandleServiceWithCallback(w http.ResponseWriter, r *http.Request, service securityprotocol.HttpHandler) (int, error, *func()) {


	var callBack *func() = nil
	if client.matchHandler != nil && !client.matchHandler(r) {
		client.Logger.Debug("No match just delegate")
		returnCode, err := client.service.Handle(w, r)
		return returnCode, err, nil
	}

	sessionId := client.sessionIdHandler.GetSessionIdFromHttpRequest(r)

	var sessionData *securityprotocol.SessionData = nil
	var tokenData *securityprotocol.TokenData
	if sessionId != "" {
		var err error
		client.Logger.Debugf("Check if we have a token cached matching the sessionId: %s", sessionId)
		tokenData, err = client.tokenCache.FindTokenDataForSessionId(sessionId)
		if err != nil {
			client.Logger.Warnf("Error (error: %s) finding token for sessionId: %s", err.Error(), sessionId)
			return http.StatusInternalServerError, err, nil
		}

		// Get sessiondata matching the session
		if client.sessionDataFetcher != nil {
			client.Logger.Debugf("Fetching sessiondata using sessionId: %s", sessionId)
			sessionData, err = client.sessionDataFetcher.GetSessionData(sessionId, client.sessionIdHandler)
			if err != nil {
				client.Logger.Infof("Error fetching sessiondata: %s", err.Error())
				return http.StatusInternalServerError, err, nil
			}
		} else {
			client.Logger.Debug("No sessionDataFetcher provided")
		}
	}

	sessionData, err := AddExtraClaimsToSessionData(sessionId, sessionData, r)
	if err != nil {
		client.Logger.Warnf("Error adding extra claims to sessiondata: %s", err.Error())
		return http.StatusInternalServerError, err, nil
	}

	if tokenData == nil || (sessionData != nil && (tokenData == nil || tokenData.Hash != sessionData.Hash)) || sessionId == "" {

		client.Logger.Debug("No token, no session, or sessiondata has changed since issueing - run authentication")
		authentication, err := client.doClientAuthentication(w, r, sessionData)
		if err != nil {
			client.Logger.Infof("Error getting token: %s", err.Error())
			return http.StatusUnauthorized, err, nil
		}
		hash := "DefaultHash"
		if sessionData != nil {
			hash = sessionData.Hash
		}

		if sessionId != "" {
			client.Logger.Debugf("Saving token for sessionid: %s expires: %s", sessionId, authentication.ExpiresIn)
			expiryDate := GetExpiryDate(authentication.ExpiresIn)
			tokenData, err = client.tokenCache.SaveAuthenticationKeysForSessionIdWithExpiry(sessionId, authentication.Token, expiryDate, hash)
			if err != nil {
				client.Logger.Infof("Cannot save sessiondata: %s", err.Error())
				return http.StatusInternalServerError, err, nil
			}
		} else {
			tokenData = &securityprotocol.TokenData{Authenticationtoken: authentication.Token}
		}
	} else {
                // We are reusing a previous session make sure that callback is set so that the tokendata kan be deleted if it turns out to be invalid
		invalidateSessionFunc := func() {
                	client.Logger.Debugf("Deleting tokendata with id %s", tokenData.ID)
                        // Invalidate stored session to trigger creation of new one on next request
                        client.tokenCache.DeleteTokenDataWithId(tokenData.ID)
		}
		callBack = &invalidateSessionFunc
	}

	// Add the authentication token to the request
	client.doDecorateRequestWithAuthenticationToken(tokenData, r)
	// Let the service do its work
	returnCode, err :=  service.Handle(w, r)
	return returnCode, err, callBack
}

func (client OioIdwsRestHttpProtocolClient) GetEncodedTokenFromSts(sessionId string, decodedToken []byte, claims map[string]string) (string, error) {

	// Get SAML assertion from STS
	var response *stsclient.StsResponse
	var err error

	if len(decodedToken) > 0 {
		client.Logger.Debugf("Get token (acting as: %s) from STS", string(decodedToken))
		response, err = client.stsClient.ActAs(client.serviceAudience, decodedToken, claims)
	} else {
		client.Logger.Debugf("Get token from STS")
		response, err = client.stsClient.GetToken(client.serviceAudience, claims)
	}
	if (err != nil) {
		client.Logger.Infof("Error getting token from STS (sessionid: %s) (error: %s)", sessionId, err.Error())
		return "", err
	}
	encodedToken := base64.StdEncoding.EncodeToString([]byte(response.ToString()))
	return encodedToken, nil
}

func (client OioIdwsRestHttpProtocolClient) doClientAuthentication(w http.ResponseWriter, r *http.Request, sessionData *securityprotocol.SessionData) (*OioIdwsRestAuthenticationInfo, error) {

	claims := make(map[string]string)
	if sessionData != nil {
		for sessionAttributeKey, sessionAttributeValue := range sessionData.SessionAttributes {
			claims[sessionAttributeKey] = sessionAttributeValue
		}
	}

	decodedToken := []byte{}
	var err error
	sessionId := "(no sessiondata as input)"
	if sessionData != nil && len(sessionData.Authenticationtoken) > 0 {
		client.Logger.Debugf("Session data found: %v", sessionData)
		// Decode it - it's base64 encoded
		decodedToken, err = base64.StdEncoding.DecodeString(sessionData.Authenticationtoken)
		if err != nil {
			client.Logger.Warnf("Error decoding token: %v", sessionData.Authenticationtoken)
			return nil, err
		}
		sessionId = sessionData.Sessionid
	}

	encodedToken, err := client.GetEncodedTokenFromSts(sessionId, decodedToken, claims)
	if err != nil {
		client.Logger.Infof("Cannot get token from STS: %s", err.Error())
		return nil, err
	}
	// Use that SAML assertion to authenticate
	url := fmt.Sprintf("%s/token", client.serviceEndpoint)
	authBody := fmt.Sprintf("saml-token=%s", encodedToken)
	client.Logger.Debugf("Getting token from service: %s", url)
	authResponse, err := client.httpClient.Post(url, "application/x-www-form-urlencoded;charset=UTF-8", bytes.NewBuffer([]byte(authBody)))
	if err != nil {
		client.Logger.Infof("Error getting token from %s: %s", url, err.Error())
		return nil, err
	}
	return CreateAuthenticatonRequestInfoFromReponse(authResponse, client.Logger)
}

func GetExpiryDate(expiresInSeconds int64) time.Time {

	expiresInTimeLimit := (expiresInSeconds * 90) / 100
	expiresInMinus5Minutes := expiresInSeconds - (5 * 60)

	expires := expiresInTimeLimit
	if (expires < expiresInMinus5Minutes) {
		expires = expiresInMinus5Minutes
	}

        expiryTime := time.Now().Add(time.Duration(expires) * time.Second)
        return expiryTime
}


func (client OioIdwsRestHttpProtocolClient) doDecorateRequestWithAuthenticationToken(tokenData *securityprotocol.TokenData, r *http.Request) error {
	r.Header.Set("Authorization", tokenData.Authenticationtoken)
	return nil
}
