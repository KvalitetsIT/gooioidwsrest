package caddyoioidwsrest

import (
	"net/http"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
	"oioidwsrest"
	securityprotocol "github.com/KvalitetsIT/gosecurityprotocol"
)

type OioIdwsCaddyHandler struct {


	clientProtocol *oioidwsrest.OioIdwsRestHttpProtocolClient
}

func NewOioIdwsRestWsdCaddyHandler(tokenCache *securityprotocol.MongoTokenCache, config *oioidwsrest.OioIdwsRestHttpProtocolClientConfig, next httpserver.Handler) (*OioIdwsCaddyHandler, error) {


	service := CaddyHandler { handler: next }
	config.Service = service

	clientProtocol := oioidwsrest.NewOioIdwsRestHttpProtocolClient(*config, tokenCache)

	oioIdwsCaddyHandler := OioIdwsCaddyHandler { clientProtocol: clientProtocol }

	return &oioIdwsCaddyHandler, nil
}


func (proxy OioIdwsCaddyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {

        return proxy.clientProtocol.Handle(w, r)
}

