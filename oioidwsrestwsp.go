package oioidwsrest

import (
	"crypto/x509"
	"io"
	"net/http"
	"crypto/sha1"
	"encoding/hex"
        uuid "github.com/google/uuid"
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

	sessionCache		*securityprotocol.SessionCache

	tokenAuthenticator	*TokenAuthenticator

	Service                 *securityprotocol.HttpHandler
}

func NewOioIdwsRestWspFromConfig(config *OioIdwsRestHttpProtocolServerConfig) *OioIdwsRestWsp {

	tokenAuthenticator := NewTokenAuthenticator(config.AudienceRestriction, config.TrustCertFiles, true)

        return NewOioIdwsRestWsp(nil, tokenAuthenticator, nil, config.Service)
}


func NewOioIdwsRestWsp(sessionCache *securityprotocol.SessionCache, tokenAuthenticator *TokenAuthenticator, matchHandler *securityprotocol.MatchHandler, service *securityprotocol.HttpHandler) *OioIdwsRestWsp{
	n := new(OioIdwsRestWsp)
	n.sessionCache = sessionCache
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
		sessionData, err := (*a.sessionCache).FindSessionDataForSessionId(sessionId)
		if (err != nil) {
			return http.StatusInternalServerError, err
		}

		if (sessionData != nil) {
			// The session id ok ... pass-through to next handler
        		return (*a.Service).Handle(w, r)
		}
	}

	// If the request is not authenticated maybe it is a request for authentication?
	assertionAsStr, authenticatedAssertion, authErr := a.tokenAuthenticator.Authenticate(sslClientCertificate, r)
	if (authErr == nil && authenticatedAssertion != nil) {

		createdSessionId := uuid.New().String()

		samlSessionDataCreator, err := securityprotocol.NewSamlSessionDataCreatorWithAssertionAndClientCert(createdSessionId, assertionAsStr, authenticatedAssertion.GetAssertion(), hashFromCertificate(sslClientCertificate))
		if (err != nil) {
			return http.StatusInternalServerError, err
		}

		sessionData, err := samlSessionDataCreator.CreateSessionData()
		if (err != nil) {
                        return http.StatusInternalServerError, err
                }

		err = (*a.sessionCache).SaveSessionData(sessionData)
		if (err != nil) {
                        return http.StatusInternalServerError, err
                }

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

func hashFromCertificate(certificate *x509.Certificate) (string) {

	if (certificate == nil) {
		return ""
	}
	hasher := sha1.New()
    	hasher.Write(certificate.Raw)
	return hex.EncodeToString(hasher.Sum(nil))
}

func getClientCertificate(req *http.Request) *x509.Certificate {

        if (len(req.TLS.PeerCertificates) > 0) {
                cert := req.TLS.PeerCertificates[0]
		return cert
        }
	return nil
}

