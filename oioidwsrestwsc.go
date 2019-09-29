package oioidwsrest

import (
        "net/http"
	"fmt"
	"bytes"

        "crypto/tls"
	"crypto/rsa"
        "crypto/x509"

        "encoding/pem"
	"encoding/base64"

	"io/ioutil"

	securityprotocol "github.com/KvalitetsIT/gosecurityprotocol"
	stsclient "github.com/KvalitetsIT/gostsclient"
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

	SessionDataFetcher	securityprotocol.SessionDataFetcher

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

func CreateCaCertPool(trustCertFiles []string) *x509.CertPool {

        caCertPool := x509.NewCertPool()
        for _, trustCertFile := range trustCertFiles {
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
	return caCertPool
}

func NewOioIdwsRestHttpProtocolClient(config OioIdwsRestHttpProtocolClientConfig, tokenCache securityprotocol.TokenCache) *OioIdwsRestHttpProtocolClient {

	// Truststore
	caCertPool := CreateCaCertPool(config.TrustCertFiles)

	// Clientkey
        clientKeyPair, err := tls.LoadX509KeyPair(config.ClientCertFile, config.ClientKeyFile)
	if (err != nil) {
		panic(err)
	}

	// Build the https client
        tlsConfig := &tls.Config{
                Certificates: []tls.Certificate{ clientKeyPair },
                RootCAs:      caCertPool,
        }
        transport := &http.Transport{ TLSClientConfig: tlsConfig }
        client := &http.Client{ Transport: transport }

	// Public key
	certFileContent, err := ioutil.ReadFile(config.ClientCertFile)
        if (err != nil) {
                panic(err)
        }
        certBlock, _ := pem.Decode([]byte(certFileContent))
        cert, err := x509.ParseCertificate(certBlock.Bytes)
        if (err != nil) {
                panic(err)
        }
        rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)

	// STSClient
        stsClient, err := stsclient.NewStsClientWithHttpClient(client, &clientKeyPair, rsaPublicKey, config.StsUrl)
	if (err != nil) {
		panic(err)
	}

	// Session handling
	sessionIdHandler := securityprotocol.HttpHeaderSessionIdHandler{ HttpHeaderName: config.SessionHeaderName }

	return newOioIdwsRestHttpProtocolClient(config.matchHandler, tokenCache, sessionIdHandler, config.SessionDataFetcher, stsClient, client, config.ServiceEndpoint, config.ServiceAudience, config.Service)
}

func newOioIdwsRestHttpProtocolClient(matchHandler securityprotocol.MatchHandler, tokenCache securityprotocol.TokenCache, sessionIdHandler securityprotocol.SessionIdHandler, sessionDataFetcher securityprotocol.SessionDataFetcher, stsClient *stsclient.StsClient, httpClient *http.Client, serviceEndpoint string, serviceAudience string, service securityprotocol.HttpHandler) (*OioIdwsRestHttpProtocolClient) {

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

	return httpProtocolClient
}

func (client OioIdwsRestHttpProtocolClient) Handle(w http.ResponseWriter, r *http.Request) (int, error) {

	fmt.Println("Enter OioIdwsRestHttpProtocolClient.Handle")

	if (client.matchHandler != nil && !client.matchHandler(r)) {
		// No match, just delegate
		return client.service.Handle(w, r)
	}

	// Check for session id
	sessionId := client.sessionIdHandler.GetSessionIdFromHttpRequest(r)

	var sessionData *securityprotocol.SessionData
	var tokenData *securityprotocol.TokenData
	if (sessionId != "") {
		var err error

		// Check if we have a token cached matching the session
        	tokenData, err = client.tokenCache.FindTokenDataForSessionId(sessionId)
        	if (err != nil) {
                	return http.StatusInternalServerError, err
        	}

       		// Get sessiondata matching the session
		if (client.sessionDataFetcher != nil) {
	        	sessionData, err = client.sessionDataFetcher.GetSessionData(sessionId, client.sessionIdHandler)
	       		if (err != nil) {
	        	        return http.StatusInternalServerError, err
	        	}
		}
	}

	if (tokenData == nil || (sessionData != nil && tokenData.Hash != sessionData.Hash) || sessionId == "") {

		// No token, no session, or sessiondata has changed since issueing - run authentication
		authentication, err := client.doClientAuthentication(w, r, sessionData)
		if (err != nil) {
			return http.StatusUnauthorized, err
		}

		hash := "DefaultHash"
		if (sessionData != nil) {
			hash = sessionData.Hash
		}

		if (sessionId != "") {
			tokenData, err = client.tokenCache.SaveAuthenticationKeysForSessionId(sessionId, authentication.Token, authentication.ExpiresIn, hash)
			if (err != nil) {
                	        return http.StatusUnauthorized, err
                	}
		} else {
			tokenData = &securityprotocol.TokenData{ Authenticationtoken: authentication.Token  }
		}
	}

	// Add the authentication token to the request
	client.doDecorateRequestWithAuthenticationToken(tokenData, r)

	// Let the service do its work
        return client.service.Handle(w, r)
}

func (client OioIdwsRestHttpProtocolClient) doClientAuthentication(w http.ResponseWriter, r *http.Request, sessionData *securityprotocol.SessionData) (*OioIdwsRestAuthenticationInfo, error) {

	fmt.Println("Enter OioIdwsRestHttpProtocolClient.doClientAuthentication")
	// Using session attributes as claims
	claims := make(map[string]string)
	if (sessionData != nil) {
		for sessionAttributeKey, sessionAttributeValue := range sessionData.SessionAttributes {
			claims[sessionAttributeKey] = sessionAttributeValue
		}
	}

	// Get SAML assertion from STS
	fmt.Println(fmt.Sprintf("OioIdwsRestHttpProtocolClient.doClientAuthentication about to get SAML Assertion from STS with audience: %s", client.serviceAudience))
        response, err := client.stsClient.GetToken(client.serviceAudience, claims)
	if (err != nil) {
		fmt.Println(err)
		return nil, err
	}

	// Use that SAML assertion to authenticate
	url := fmt.Sprintf("%s/token", client.serviceEndpoint)
	encodedToken := base64.StdEncoding.EncodeToString([]byte(response.ToString()))
	authBody := fmt.Sprintf("saml-token=%s", encodedToken)
	fmt.Println(fmt.Sprintf("OioIdwsRestHttpProtocolClient.doClientAuthentication about to authenticate: %s", authBody))
	authResponse, err := client.httpClient.Post(url, "application/x-www-form-urlencoded;charset=UTF-8", bytes.NewBuffer([]byte(authBody)))
	if (err != nil) {
		return nil, err
	}
	return CreateAuthenticatonRequestInfoFromReponse(authResponse)
}

func (client OioIdwsRestHttpProtocolClient) doDecorateRequestWithAuthenticationToken(tokenData *securityprotocol.TokenData, r *http.Request) error {
	r.Header.Add("Authorization", tokenData.Authenticationtoken)
	return nil
}
