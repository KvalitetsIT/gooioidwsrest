package caddyoioidwsrest

import (
	"fmt"
	"net/http"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

type CaddyHandler struct {
	handler httpserver.Handler
}


func (caddy CaddyHandler) Handle(response http.ResponseWriter, request *http.Request) (int, error) {
	fmt.Println("Enter CaddyHandler.Handle")
	if (caddy.handler == nil) {
		panic(fmt.Errorf("CaddyHandler.handler is nil"))
	}
	res, err := caddy.handler.ServeHTTP(response, request)
	return res, err
}
