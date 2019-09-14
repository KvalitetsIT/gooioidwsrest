package oioidwsrest

import (
        "net/http"
	"fmt"
	securityprotocol "github.com/KvalitetsIT/gosecurityprotocol"
	stsclient "github.com/KvalitetsIT/gostsclient"
	uuid "github.com/google/uuid"
)


type OioIdwsRestAuthenticationInfo struct {

        Token           string
        ExpiresIn       int64
}

type OioIdwsRestClientAuthentification func(http.ResponseWriter, *http.Request, *securityprotocol.SessionData) (*OioIdwsRestAuthenticationInfo, int, error)

type OioIdwsRestDecorateRequestWithAuthenticationToken func(tokenData *securityprotocol.TokenData, r *http.Request) error


type OioIdwsRestHttpProtocolClient struct {

	matchHandler		securityprotocol.MatchHandler

	tokenCache      	securityprotocol.TokenCache

	sessionIdHandler	securityprotocol.SessionIdHandler
	sessionDataFetcher	securityprotocol.SessionDataFetcher

	stsClient		*stsclient.StsClient

//	preAuthentication	PreAuthentication
	decorateRequest		OioIdwsRestDecorateRequestWithAuthenticationToken

	service			securityprotocol.HttpHandler
}

func NewOioIdwsRestHttpProtocolClient(matchHandler securityprotocol.MatchHandler, tokenCache securityprotocol.TokenCache, sessionIdHandler securityprotocol.SessionIdHandler, sessionDataFetcher securityprotocol.SessionDataFetcher, stsClient *stsclient.StsClient, service securityprotocol.HttpHandler) (*OioIdwsRestHttpProtocolClient) {

	httpProtocolClient := new(OioIdwsRestHttpProtocolClient)
	httpProtocolClient.matchHandler = matchHandler
	httpProtocolClient.tokenCache = tokenCache
	httpProtocolClient.sessionIdHandler = sessionIdHandler
	httpProtocolClient.sessionDataFetcher = sessionDataFetcher
	httpProtocolClient.decorateRequest = DoOioIdwsRestDecorateRequestWithAuthenticationToken
	httpProtocolClient.stsClient = stsClient
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

		/*if (client.preAuthentication != nil) {
			httpCode, err := client.preAuthentication(w, r, sessionData)
			if (err != nil || httpCode > 0) {
				return httpCode, err
			}
		}*/

		// No token - or sessiondata has changed since issueing - run authentication
		authentication, authStatusCode, err := client.doClientAuthentication(w, r, sessionData)
		if (err != nil || (authStatusCode != http.StatusOK)) {
			return http.StatusUnauthorized, nil
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
                        return http.StatusUnauthorized, nil
                }

		// Some response was generated during authentication (for instance a redirect) - we are done!
		if (authStatusCode > 0) {
			return authStatusCode, nil
		}
	}

	// Add the authentication token to the request
	client.decorateRequest(tokenData, r)

	// Let the service do its work
        return client.service.Handle(w, r)
}

func (client OioIdwsRestHttpProtocolClient) doClientAuthentication(w http.ResponseWriter, r *http.Request, s *securityprotocol.SessionData) (*OioIdwsRestAuthenticationInfo, int, error) {

	audience := "urn:kit:testa:servicea"
	claims := make(map[string]string)
	// TODO Claims

        // When
        response, err := client.stsClient.GetToken(audience, claims)
	if (err != nil) {
		return nil, http.StatusUnauthorized, err
	}

	return &OioIdwsRestAuthenticationInfo{ Token: response.ToString(), ExpiresIn: 10000 }, http.StatusOK, nil
}

func DoOioIdwsRestDecorateRequestWithAuthenticationToken(tokenData *securityprotocol.TokenData, r *http.Request) error {

	return nil
}

/*
type OioIdwsRestWsc struct {
	sessionHeaderName string
	sessionStore *SessionStore
	next httpserver.Handler
}

func NewOioIdwsRestWsc(sessionHeaderName string, sessionStore *SessionStore, next httpserver.Handler) *OioIdwsRestWsp{
	n := new(OioIdwsRestWsp)
	n.sessionHeaderName = sessionHeaderName
	n.sessionStore = sessionStore
	n.next = next
	return n
}

func (a OioIdwsRestWsc) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {

	// TODO: Check that the request is a HTTPS request and that it contains a client certificate

	sessionId := a.getSessionId(r)

	// The request identifies a session, check that the session is valid and get it
	if (sessionId != "") {
		session, _ := a.sessionStore.GetValidSessionFromId(sessionId)

		if (session != nil) {
			// The session id ok ... pass-through to next handler
        		return a.next.ServeHTTP(w, r)
		}
	}

	return a.next.ServeHTTP(w, r)

}


func (a OioIdwsRestWsc) getSessionId(r *http.Request) (string) {
	sessionId := r.Header.Get(a.sessionHeaderName)
	return sessionId
}
*/
