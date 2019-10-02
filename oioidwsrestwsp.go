package oioidwsrest

import (
	"crypto/x509"
	"io"
	"net/http"
	securityprotocol "github.com/KvalitetsIT/gosecurityprotocol"
)

const HEADER_WWW_AUTHENTICATE = "WWW-Authenticate"
const HEADER_AUTHORIZATION = "Authorization"


type OioIdwsRestHttpProtocolServerConfig struct {

	TrustCertFiles          []string

	AudienceRestriction	string

	Service                 *securityprotocol.HttpHandler
}

type OioIdwsRestWsp struct {

	matchHandler		*securityprotocol.MatchHandler

//	sessionStore		*securityprotocol.SessionStore

	tokenAuthenticator	*TokenAuthenticator

	Service                 *securityprotocol.HttpHandler
}

func NewOioIdwsRestWspFromConfig(config *OioIdwsRestHttpProtocolServerConfig) *OioIdwsRestWsp {

	tokenAuthenticator := NewTokenAuthenticator(config.AudienceRestriction, config.TrustCertFiles, true)

        return NewOioIdwsRestWsp(/*nil,*/ tokenAuthenticator, nil, config.Service)
}


func NewOioIdwsRestWsp(/*sessionStore *SessionStore,*/ tokenAuthenticator *TokenAuthenticator, matchHandler *securityprotocol.MatchHandler, service *securityprotocol.HttpHandler) *OioIdwsRestWsp{
	n := new(OioIdwsRestWsp)
	//n.SessionStore = sessionStore
	n.tokenAuthenticator = tokenAuthenticator
	return n
}


func (a OioIdwsRestWsp) Handle(w http.ResponseWriter, r *http.Request) (int, error) {


	// Check that the request is a HTTPS request and that it contains a client certificate
        sslClientCertificate := getClientCertificate(r)
	if (sslClientCertificate == nil) {
                return http.StatusBadRequest, nil
	}

	// Get the session id
	sessionId := a.getSessionId(r)

	// The request identifies a session, check that the session is valid and get it
	// TODO: and that HoK is ok
	if (sessionId != "") {
		var session *securityprotocol.SessionData /*, _ := a.sessionStore.GetValidSessionFromId(sessionId)*/

		if (session != nil) {
			// The session id ok ... pass-through to next handler
        		// TODO kommenter ind return a.Service.Handle(w, r)
		}
	}

	// If the request is not authenticated maybe it is a request for authentication?
	createdSessionId, _,  authErr := a.tokenAuthenticator.Authenticate(sslClientCertificate, r)
	if (authErr == nil && createdSessionId != "") {
		// Succesful authentication
		io.WriteString(w, createdSessionId)
		return http.StatusOK, nil
	}

	// The authentication process failed
	if (authErr != nil) {
		w.Header().Set(HEADER_WWW_AUTHENTICATE, authErr.Error())
	}

        return http.StatusUnauthorized, authErr
}

func (a OioIdwsRestWsp) getSessionId(r *http.Request) (string) {
	sessionId := r.Header.Get(HEADER_AUTHORIZATION)
	return sessionId
}

func getClientCertificate(req *http.Request) *x509.Certificate {

        if (len(req.TLS.PeerCertificates) > 0) {
                cert := req.TLS.PeerCertificates[0]
		return cert
        }
	return nil
}

