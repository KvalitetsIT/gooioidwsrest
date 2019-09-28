package caddyoioidwsrest

import (
	"net/http"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

type CaddyHandler struct {
	handler httpserver.Handler
}


func (caddy CaddyHandler) Handle(response http.ResponseWriter, request *http.Request) (int, error) {
	res, err := caddy.handler.ServeHTTP(response, request)
	return res, err
}
