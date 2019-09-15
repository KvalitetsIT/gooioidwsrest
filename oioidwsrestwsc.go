package oioidwsrest

import (
        "net/http"
	"fmt"
	"bytes"

        "crypto/tls"
        "crypto/x509"

        "encoding/pem"
	"encoding/base64"

	"io/ioutil"

	securityprotocol "github.com/KvalitetsIT/gosecurityprotocol"
	stsclient "github.com/KvalitetsIT/gostsclient"
	uuid "github.com/google/uuid"
)


type OioIdwsRestAuthenticationInfo struct {

        Token           string
        ExpiresIn       int64
}

type OioIdwsRestHttpProtocolClientConfig struct {

	matchHandler		securityprotocol.MatchHandler

	SessionHeaderName	string

	StsUrl			string
	TrustCertFiles		[]string

	ClientCertFile		string
	ClientKeyFile		string

	ServiceAudience		string
	ServiceEndpoint		string

	SessionFetchUrl		string

	Service			securityprotocol.HttpHandler
}

type OioIdwsRestClientAuthentification func(http.ResponseWriter, *http.Request, *securityprotocol.SessionData) (*OioIdwsRestAuthenticationInfo, int, error)

type OioIdwsRestDecorateRequestWithAuthenticationToken func(tokenData *securityprotocol.TokenData, r *http.Request) error

type OioIdwsRestHttpProtocolClient struct {

	matchHandler		securityprotocol.MatchHandler

	tokenCache      	securityprotocol.TokenCache

	sessionIdHandler	securityprotocol.SessionIdHandler
	sessionDataFetcher	securityprotocol.SessionDataFetcher

	stsClient		*stsclient.StsClient
	httpClient		*http.Client

	decorateRequest		OioIdwsRestDecorateRequestWithAuthenticationToken

	serviceEndpoint		string
	serviceAudience		string

	service			securityprotocol.HttpHandler
}

func NewOioIdwsRestHttpProtocolClient(config OioIdwsRestHttpProtocolClientConfig, tokenCache securityprotocol.TokenCache) *OioIdwsRestHttpProtocolClient {

	// Truststore
	caCertPool := x509.NewCertPool()
	for _, trustCertFile := range config.TrustCertFiles {
		trustCert, err := ioutil.ReadFile(trustCertFile)
        	if (err != nil) {
                	panic(err)
        	}
        	trustBlock, _ := pem.Decode([]byte(trustCert))
        	if (err != nil) {
                	panic(err)
        	}
        	certToTrust, err := x509.ParseCertificate(trustBlock.Bytes)
        	if (err != nil) {
                	panic(err)
        	}
		caCertPool.AddCert(certToTrust)
	}

	// Clientkey
        clientKeyPair, err := tls.LoadX509KeyPair(config.ClientCertFile, config.ClientKeyFile)
	if (err != nil) {
		panic(err)
	}

	// Buidl the https client
        tlsConfig := &tls.Config{
                Certificates: []tls.Certificate{ clientKeyPair },
                RootCAs:      caCertPool,
        }
        transport := &http.Transport{ TLSClientConfig: tlsConfig }
        client := &http.Client{ Transport: transport }

        stsClient, err := stsclient.NewStsClientWithHttpClient(client, &clientKeyPair, config.StsUrl)
	if (err != nil) {
		panic(err)
	}

	sessionIdHandler := securityprotocol.HttpHeaderSessionIdHandler{ HttpHeaderName: config.SessionHeaderName }

	var sessionDataFetcher *securityprotocol.ServiceCallSessionDataFetcher
	if (len(config.SessionFetchUrl) > 0) {
		sessionDataFetcher = &securityprotocol.ServiceCallSessionDataFetcher{ SessionDataServiceEndpoint: config.SessionFetchUrl }
	}

	return newOioIdwsRestHttpProtocolClient(config.matchHandler, tokenCache, sessionIdHandler, sessionDataFetcher, stsClient, client, config.ServiceEndpoint, config.ServiceAudience, config.Service)
}

func newOioIdwsRestHttpProtocolClient(matchHandler securityprotocol.MatchHandler, tokenCache securityprotocol.TokenCache, sessionIdHandler securityprotocol.SessionIdHandler, sessionDataFetcher securityprotocol.SessionDataFetcher, stsClient *stsclient.StsClient, httpClient *http.Client, serviceEndpoint string, serviceAudience string, service securityprotocol.HttpHandler) (*OioIdwsRestHttpProtocolClient) {

	httpProtocolClient := new(OioIdwsRestHttpProtocolClient)
	httpProtocolClient.matchHandler = matchHandler
	httpProtocolClient.tokenCache = tokenCache
	httpProtocolClient.sessionIdHandler = sessionIdHandler
	httpProtocolClient.sessionDataFetcher = sessionDataFetcher
	httpProtocolClient.decorateRequest = DoOioIdwsRestDecorateRequestWithAuthenticationToken
	httpProtocolClient.stsClient = stsClient
	httpProtocolClient.httpClient = httpClient
	httpProtocolClient.serviceEndpoint = serviceEndpoint
	httpProtocolClient.serviceAudience = serviceAudience
	httpProtocolClient.service = service

	return httpProtocolClient
}

func (client OioIdwsRestHttpProtocolClient) Handle(w http.ResponseWriter, r *http.Request) (int, error) {

	if (!client.matchHandler(r)) {
		// No match, just delegate
		return client.service.Handle(w, r)
	}

	// Check for session id
	sessionId := client.sessionIdHandler.GetSessionIdFromHttpRequest(r)

	var sessionData *securityprotocol.SessionData
	var tokenData *securityprotocol.TokenData
	if (sessionId != "") {
		var err error

		// Check if we have a token cached
        	tokenData, err = client.tokenCache.FindTokenDataForSessionId(sessionId)
        	if (err != nil) {
                	fmt.Println(fmt.Sprintf("Error in FindTokenDataForSessionId: %s (error:%v)", sessionId, err))
                	return http.StatusInternalServerError, err
        	}

       		// Get sessiondata
        	sessionData, err = client.sessionDataFetcher.GetSessionData(sessionId, client.sessionIdHandler)
        	if (err != nil) {
        	        fmt.Println(fmt.Sprintf("Error in GetSessionData: %s (error:%v)", sessionId, err))
	                return http.StatusInternalServerError, err
	        }
	}

	if (tokenData == nil || (tokenData.Hash != sessionData.Hash) || sessionId == "") {

		// No token, no session, or sessiondata has changed since issueing - run authentication
		authentication, err := client.doClientAuthentication(w, r, sessionData)
		if (err != nil) {
			return http.StatusUnauthorized, err
		}

		if (sessionId == "") {
			// Authorization succeded - generate session id
			sessionId = uuid.New().String()
 		}

		hash := "DefaultHash"
		if (sessionData != nil) {
			hash = sessionData.Hash
		}

		tokenData, err = client.tokenCache.SaveAuthenticationKeysForSessionId(sessionId, authentication.Token, authentication.ExpiresIn, hash)
		if (err != nil) {
                        return http.StatusUnauthorized, err
                }
	}

	// Add the authentication token to the request
	client.decorateRequest(tokenData, r)

	// Let the service do its work
        return client.service.Handle(w, r)
}

func (client OioIdwsRestHttpProtocolClient) doClientAuthentication(w http.ResponseWriter, r *http.Request, s *securityprotocol.SessionData) (*OioIdwsRestAuthenticationInfo, error) {

	claims := make(map[string]string)
	// TODO map Claims from sessionattr in sessiondata

	// Get SAML assertion from STS
        response, err := client.stsClient.GetToken(client.serviceAudience, claims)
	if (err != nil) {
		return nil, err
	}

	// Use that SAML assertion to authenticate
	url := fmt.Sprintf("%s/token", client.serviceEndpoint)
	encodedToken := base64.StdEncoding.EncodeToString([]byte(response.ToString()))
	authBody := fmt.Sprintf("saml-token=%s", encodedToken)
	authResponse, err := client.httpClient.Post(url, "application/x-www-form-urlencoded;charset=UTF-8", bytes.NewBuffer([]byte(authBody)))
	if (err != nil) {
		return nil, err
	}
	if (authResponse.StatusCode != http.StatusOK) {
		return nil, fmt.Errorf(fmt.Sprintf("Authentication failed url:%s body=%s", url, authBody))
	}

	return &OioIdwsRestAuthenticationInfo{ Token: response.ToString(), ExpiresIn: 10000 }, nil
}

func DoOioIdwsRestDecorateRequestWithAuthenticationToken(tokenData *securityprotocol.TokenData, r *http.Request) error {

	return nil
}
