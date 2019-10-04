package oioidwsrest

import (
        "net/http"
	"fmt"
	"bytes"

	"log"

        "crypto/tls"
	"crypto/rsa"
        "crypto/x509"

        "encoding/pem"
	"encoding/base64"

	"io/ioutil"

	securityprotocol "github.com/KvalitetsIT/gosecurityprotocol"
	stsclient "github.com/KvalitetsIT/gostsclient"
)


const HTTP_HEADER_X_CLAIMS = "X-Claims"


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

	fmt.Println("Enter OioIdwsRestHttpProtocolClient.Handle 1")

	if (client.matchHandler != nil && !client.matchHandler(r)) {
		// No match, just delegate
		return client.service.Handle(w, r)
	}

	// Check for session id
	fmt.Println("Enter OioIdwsRestHttpProtocolClient.Handle 2")
	sessionId := client.sessionIdHandler.GetSessionIdFromHttpRequest(r)

	var sessionData *securityprotocol.SessionData = nil
	var tokenData *securityprotocol.TokenData
	if (sessionId != "") {
		var err error

		// Check if we have a token cached matching the session
	        fmt.Println("Enter OioIdwsRestHttpProtocolClient.Handle 2.1")
        	tokenData, err = client.tokenCache.FindTokenDataForSessionId(sessionId)
        	if (err != nil) {
			log.Println("[ERROR] failed to find tokendata for session: ", err)
                	return http.StatusInternalServerError, err
        	}

       		// Get sessiondata matching the session
                fmt.Println("Enter OioIdwsRestHttpProtocolClient.Handle 2.2")
		if (client.sessionDataFetcher != nil) {
	        	sessionData, err = client.sessionDataFetcher.GetSessionData(sessionId, client.sessionIdHandler)
	       		if (err != nil) {
                       		log.Println("[ERROR] failed get sessiondata: ", err)
	        	        return http.StatusInternalServerError, err
	        	}
		}
	}

	sessionData, err := AddExtraClaimsToSessionData(sessionId, sessionData, r)
	if (err != nil) {
		log.Println("[ERROR] failed add sessiondata from headers: ", err)
	}

        fmt.Println("Enter OioIdwsRestHttpProtocolClient.Handle 3")
	if (tokenData == nil || (sessionData != nil && (tokenData == nil || tokenData.Hash != sessionData.Hash)) || sessionId == "") {

		// No token, no session, or sessiondata has changed since issueing - run authentication
		authentication, err := client.doClientAuthentication(w, r, sessionData)
		if (err != nil) {
                       	log.Println("[ERROR] failed to authenticate: ", err)
			return http.StatusUnauthorized, err
		}

		hash := "DefaultHash"
		if (sessionData != nil) {
			hash = sessionData.Hash
		}

		fmt.Println("Enter OioIdwsRestHttpProtocolClient.Handle 3.1")
		if (sessionId != "") {
			tokenData, err = client.tokenCache.SaveAuthenticationKeysForSessionId(sessionId, authentication.Token, authentication.ExpiresIn, hash)
			if (err != nil) {
	                        log.Println("[ERROR] failed to save authentication keys for session: ", err)
                	        return http.StatusUnauthorized, err
                	}
		} else {
			tokenData = &securityprotocol.TokenData{ Authenticationtoken: authentication.Token  }
		}
	}

	fmt.Println("Enter OioIdwsRestHttpProtocolClient.Handle 4")
	// Add the authentication token to the request
	client.doDecorateRequestWithAuthenticationToken(tokenData, r)


	fmt.Println("Enter OioIdwsRestHttpProtocolClient.Handle 5")
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
	var response *stsclient.StsResponse
	var err error

	fmt.Println(fmt.Sprintf("OioIdwsRestHttpProtocolClient.doClientAuthentication about to get SAML Assertion from STS with audience: %s", client.serviceAudience))
	if (sessionData != nil && len(sessionData.Authenticationtoken) > 0) {
		// Decode it - it's base64 encoded
		decodedToken, err := base64.StdEncoding.DecodeString(sessionData.Authenticationtoken)
        	if (err != nil) {
                	return nil, err
        	}
		response, err = client.stsClient.ActAs(client.serviceAudience, decodedToken, claims)
	} else {
        	response, err = client.stsClient.GetToken(client.serviceAudience, claims)
	}
	if (err != nil) {
                log.Println("[ERROR] failed to get token from STS: ", err)
		return nil, err
	}

	// Use that SAML assertion to authenticate
	url := fmt.Sprintf("%s/token", client.serviceEndpoint)
	encodedToken := base64.StdEncoding.EncodeToString([]byte(response.ToString()))
	authBody := fmt.Sprintf("saml-token=%s", encodedToken)
	fmt.Println(fmt.Sprintf("OioIdwsRestHttpProtocolClient.doClientAuthentication about to authenticate: %s", authBody))
	authResponse, err := client.httpClient.Post(url, "application/x-www-form-urlencoded;charset=UTF-8", bytes.NewBuffer([]byte(authBody)))
	if (err != nil) {
                log.Println("[ERROR] failed to parse authentication response body: ", err)
		return nil, err
	}
	fmt.Println(fmt.Sprintf("OioIdwsRestHttpProtocolClient.doClientAuthentication about to parse response:"))
	return CreateAuthenticatonRequestInfoFromReponse(authResponse)
}

func (client OioIdwsRestHttpProtocolClient) doDecorateRequestWithAuthenticationToken(tokenData *securityprotocol.TokenData, r *http.Request) error {
	fmt.Println(fmt.Sprintf("OioIdwsRestHttpProtocolClient.doDecorateRequestWithAuthenticationToken token:%s", tokenData.Authenticationtoken))
	r.Header.Add("Authorization", tokenData.Authenticationtoken)
	return nil
}
