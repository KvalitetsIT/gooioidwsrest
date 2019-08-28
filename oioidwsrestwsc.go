package oioidwsrest

import (
//	"fmt"
//	"io"
//	"net/http"
//	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

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
