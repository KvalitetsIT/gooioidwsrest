package oioidwsrest

import (
	"fmt"
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

	sessionCache		securityprotocol.SessionCache

	tokenAuthenticator	*TokenAuthenticator

	Service                 *securityprotocol.HttpHandler

	ClientCertHandler	func(req *http.Request) *x509.Certificate
}

func NewOioIdwsRestWspFromConfig(config *OioIdwsRestHttpProtocolServerConfig, sessionCache securityprotocol.SessionCache) *OioIdwsRestWsp {

	tokenAuthenticator := NewTokenAuthenticator(config.AudienceRestriction, config.TrustCertFiles, true)

        return NewOioIdwsRestWsp(sessionCache, tokenAuthenticator, nil, config.Service)
}


func NewOioIdwsRestWsp(sessionCache securityprotocol.SessionCache, tokenAuthenticator *TokenAuthenticator, matchHandler *securityprotocol.MatchHandler, service *securityprotocol.HttpHandler) *OioIdwsRestWsp{
	n := new(OioIdwsRestWsp)
	n.sessionCache = sessionCache
	n.tokenAuthenticator = tokenAuthenticator
	n.ClientCertHandler = getClientCertificate
	return n
}


func (a OioIdwsRestWsp) Handle(w http.ResponseWriter, r *http.Request) (int, error) {


	fmt.Println("wsp handle 1")
	// Check that the request is a HTTPS request and that it contains a client certificate
        sslClientCertificate := a.ClientCertHandler(r)
	if (sslClientCertificate == nil) {
                return http.StatusBadRequest, fmt.Errorf("SSL Client Certificate must be supplied (HoK)")
	}
        fmt.Println("wsp handle 2")

	// Get the session id
	sessionId := a.getSessionId(r)

        fmt.Println("wsp handle 3")
	// The request identifies a session, check that the session is valid and get it
	// TODO: and that HoK is ok
	if (sessionId != "") {
		sessionData, err := a.sessionCache.FindSessionDataForSessionId(sessionId)
		if (err != nil) {
			return http.StatusInternalServerError, err
		}

		if (sessionData != nil) {
			// The session id ok ... pass-through to next handler
        		return (*a.Service).Handle(w, r)
		}
	}

	// If the request is not authenticated maybe it is a request for authentication?
	fmt.Println("wsp handle 4")
	assertionAsStr, authenticatedAssertion, authErr := a.tokenAuthenticator.Authenticate(sslClientCertificate, r)
	if (authErr == nil && authenticatedAssertion != nil) {

		fmt.Println("wsp handle 4.1")
		createdSessionId := uuid.New().String()

		samlSessionDataCreator, err := securityprotocol.NewSamlSessionDataCreatorWithAssertionAndClientCert(createdSessionId, assertionAsStr, authenticatedAssertion.GetAssertion(), hashFromCertificate(sslClientCertificate))
		if (err != nil) {
			return http.StatusInternalServerError, err
		}

		sessionData, err := samlSessionDataCreator.CreateSessionData()
		if (err != nil) {
                        return http.StatusInternalServerError, err
                }

		err = a.sessionCache.SaveSessionData(sessionData)
		if (err != nil) {
                        return http.StatusInternalServerError, err
                }

		// Succesful authentication
		io.WriteString(w, createdSessionId)
		return http.StatusOK, nil
	}
	fmt.Println("wsp handle 5")

	// The authentication process failed
	if (authErr != nil) {
		fmt.Println(fmt.Sprintf("wsp handle 6 %s", authErr.Error()))
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

	fmt.Println("getclientcert0")
        if (len(req.TLS.PeerCertificates) > 0) {
		fmt.Println("getclientcert1")
                cert := req.TLS.PeerCertificates[0]
		return cert
        }
	return nil
}

