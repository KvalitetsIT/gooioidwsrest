package oioidwsrest

import (
	"fmt"
	"crypto/x509"
	"net/http"
	"crypto/sha1"
	"encoding/hex"
	"strings"
        uuid "github.com/google/uuid"
	securityprotocol "github.com/KvalitetsIT/gosecurityprotocol"
	"go.uber.org/zap"
)

const HEADER_WWW_AUTHENTICATE = "WWW-Authenticate"
const HEADER_AUTHORIZATION = "Authorization"

type OioIdwsRestHttpProtocolServerConfig struct {

	TrustCertFiles          []string

	AudienceRestriction	string

	Service                 securityprotocol.HttpHandler

	HoK			bool
}

type OioIdwsRestWsp struct {

	matchHandler		*securityprotocol.MatchHandler

	sessionCache		securityprotocol.SessionCache

	tokenAuthenticator	*TokenAuthenticator

	Service                 securityprotocol.HttpHandler

	HoK			bool

	ClientCertHandler	func(req *http.Request) *x509.Certificate

	Logger *zap.SugaredLogger
}

func NewOioIdwsRestWspFromConfig(config *OioIdwsRestHttpProtocolServerConfig, sessionCache securityprotocol.SessionCache, logger *zap.SugaredLogger) *OioIdwsRestWsp {

	tokenAuthenticator := NewTokenAuthenticator(config.AudienceRestriction, config.TrustCertFiles, true, logger)
        wsp := NewOioIdwsRestWsp(sessionCache, tokenAuthenticator, nil, config.Service,logger)
	wsp.HoK = config.HoK
	return wsp
}


func NewOioIdwsRestWsp(sessionCache securityprotocol.SessionCache, tokenAuthenticator *TokenAuthenticator, matchHandler *securityprotocol.MatchHandler, service securityprotocol.HttpHandler, logger *zap.SugaredLogger) *OioIdwsRestWsp{
	n := new(OioIdwsRestWsp)
	n.sessionCache = sessionCache
	n.tokenAuthenticator = tokenAuthenticator
	n.ClientCertHandler = getClientCertificate
	n.Service = service
	n.HoK = true
	n.Logger = logger
	return n
}

func (a OioIdwsRestWsp) Handle(w http.ResponseWriter, r *http.Request) (int, error) {
        return a.HandleService(w, r, a.Service)
}

func (a OioIdwsRestWsp) HandleService(w http.ResponseWriter, r *http.Request, service securityprotocol.HttpHandler) (int, error) {


	// Check that the request is a HTTPS request and that it contains a client certificate
        var sslClientCertificate *x509.Certificate
	if (a.HoK) {
	   sslClientCertificate = a.ClientCertHandler(r)
	   if (sslClientCertificate == nil) {
		a.Logger.Warn("The client did not provide a certificate")
       	   	return http.StatusBadRequest, fmt.Errorf("SSL Client Certificate must be supplied (HoK)")
	   }
	}

	// Get the session id
	sessionId, err := a.getSessionId(r)
	if (err != nil) {
	    	a.Logger.Warnf("The client did provide SessionId: %v",err)
		return http.StatusUnauthorized, err
	}

	// The request identifies a session, check that the session is valid and get it
	if (sessionId != "") {
		a.Logger.Debug(fmt.Sprintf("Sessionid received: %s", sessionId))
		sessionData, err := a.sessionCache.FindSessionDataForSessionId(sessionId)
		if (err != nil) {
		    	a.Logger.Warnf("Cannot look up sessiondata: %v",err)
			return http.StatusInternalServerError, err
		}

		if (sessionData != nil) {
            		a.Logger.Debug(fmt.Sprintf("Sessiondata for sessionid: %s not found", sessionId))

			// Validate HoK
			hashFromClientCert := hashFromCertificate(sslClientCertificate)
			if (a.HoK && hashFromClientCert != sessionData.ClientCertHash) {
				a.Logger.Info(fmt.Sprintf("Client certificate not HoK (sessionid: %s)", sessionId))
				return http.StatusUnauthorized, fmt.Errorf("Client certificate not HoK")
			}

			// Check if the user is requesting sessiondata
			handlerFunc := securityprotocol.IsRequestForSessionData(sessionData, a.sessionCache, w, r)
			if (handlerFunc != nil) {
				a.Logger.Debug(fmt.Sprintf("Getting sessiondata (sessionid: %s)", sessionId))
				return handlerFunc()
			}

			// The session id ok ... pass-through to next handler
			a.Logger.Debug("Calling backend service")
            		return service.Handle(w, r)
		}
	}

	a.Logger.Debug("If the request is not authenticated maybe it is a request for authentication?")
	assertionAsStr, authenticatedAssertion, authErr := a.tokenAuthenticator.Authenticate(sslClientCertificate, r)
	if (authErr == nil && authenticatedAssertion != nil) {
		createdSessionId := uuid.New().String()
		a.Logger.Debug(fmt.Sprintf("Client authenticated creating session with id: %s", createdSessionId))

		samlSessionDataCreator, err := securityprotocol.NewSamlSessionDataCreatorWithAssertionAndClientCert(createdSessionId, assertionAsStr, authenticatedAssertion.GetAssertion(), hashFromCertificate(sslClientCertificate))
		if (err != nil) {
			a.Logger.Warnf(fmt.Sprintf("Error creating sessiondata from assertion and clientcert (err: %s)", err.Error()))
			return http.StatusInternalServerError, err
		}

		sessionData, err := samlSessionDataCreator.CreateSessionData()
		if (err != nil) {
			a.Logger.Warnf(fmt.Sprintf("Error creating sessiondata (err: %s)", err.Error()))
                        return http.StatusInternalServerError, err
                }

		err = a.sessionCache.SaveSessionData(sessionData)
		if (err != nil) {
		   a.Logger.Warnf("Cannot save sessiondata: %v",err)
           	   return http.StatusInternalServerError, err
        	}

		// Succesful authentication
		resCode, err := ResponseWithSuccessfulAuth(w, sessionData,a.Logger)
		if (err != nil) {
			a.Logger.Warnf(fmt.Sprintf("Creating authentication response (err: %s)", err.Error()))
			return http.StatusUnauthorized, err
		}
		return resCode, nil
	}

	// The authentication process failed
	if (authErr != nil) {
		w.Header().Set(HEADER_WWW_AUTHENTICATE, authErr.Error())
	}

        return http.StatusUnauthorized, authErr
}

func (a OioIdwsRestWsp) getSessionId(r *http.Request) (string, error) {
	sessionId := r.Header.Get(HEADER_AUTHORIZATION)
	if (sessionId  != "") {
		sessionIdParts := strings.Split(sessionId, " ")
		if (len(sessionIdParts) == 2) {
			return sessionIdParts[1], nil
		}
		return "", fmt.Errorf(fmt.Sprintf("%s header contains illegal value: %s", HEADER_AUTHORIZATION, sessionId))
	}
	return "", nil
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

	if (req.TLS != nil) {
	        if (len(req.TLS.PeerCertificates) > 0) {
        	        cert := req.TLS.PeerCertificates[0]
			return cert
        	}
	}
	return nil
}

