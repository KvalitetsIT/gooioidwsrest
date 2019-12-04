package caddyoioidwsrest

import (

	"fmt"
	"strconv"
	"oioidwsrest"
	securityprotocol "github.com/KvalitetsIT/gosecurityprotocol"
	"net/http"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)


type CaddyOioIdwsRestWsp struct {

	MongoHost string `json:"mongo_host,omitempty"`

	MongoPort string `json:"mongo_port,omitempty"`

	MongoDb string `json:"mongo_db,omitempty"`

	TrustCertFiles []string `json:"trust_cert_files,omitempty"`

	AudienceRestriction string `json:"audience_restriction,omitempty"`

	ProviderProtocol *oioidwsrest.OioIdwsRestWsp
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m CaddyOioIdwsRestWsp) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {

	nextService := new(CaddyService)
	nextService.Handler = next

	fmt.Println("CADDYWSP 1")
	httpCode, err := m.ProviderProtocol.HandleService(w, r, nextService)
	fmt.Println(fmt.Sprintf("CADDYWSP 2 returcode:%d  ok?%d", httpCode, http.StatusOK))
	if (httpCode != http.StatusOK) {
		fmt.Println("CADDYWSP 3")
		return caddyhttp.Error(httpCode, err)
	}

	return nil
}



func init() {
	caddy.RegisterModule(CaddyOioIdwsRestWsp{})
	httpcaddyfile.RegisterHandlerDirective("oioidwsrestwsp", parseCaddyfileWsc)
}

// CaddyModule returns the Caddy module information.
func (CaddyOioIdwsRestWsp) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		Name: "http.handlers.oioidwsrestwsp",
		New:  func() caddy.Module { return new(CaddyOioIdwsRestWsp) },
	}
}

// Provision implements caddy.Provisioner.
func (m *CaddyOioIdwsRestWsp) Provision(ctx caddy.Context) error {

	// Create Mongo Token Cache
	mongo_port := "27017"
	if (len(m.MongoPort) != 0) {
		_, conv_err := strconv.Atoi(m.MongoPort)
        	if (conv_err != nil) {
                	return conv_err
        	}
		mongo_port = m.MongoPort
        }
	mongo_url := fmt.Sprintf("%s:%s", m.MongoHost, mongo_port)
	sessionCache, err := securityprotocol.NewMongoSessionCache(mongo_url, m.MongoDb, "sessions")
	if (err != nil) {
		return err
	}

	// Maps to wsc config
        wspConfig := new(oioidwsrest.OioIdwsRestHttpProtocolServerConfig)
        wspConfig.TrustCertFiles = m.TrustCertFiles
        wspConfig.AudienceRestriction = m.AudienceRestriction

	m.ProviderProtocol = oioidwsrest.NewOioIdwsRestWspFromConfig(wspConfig, sessionCache)

	return nil
}

// Validate implements caddy.Validator.
func (m *CaddyOioIdwsRestWsp) Validate() error {

	if (len(m.MongoHost) == 0) {
		return fmt.Errorf("mongo_host must be configured")
	}

        if (len(m.MongoDb) == 0) {
                return fmt.Errorf("mongo_db must be configured")
        }

	return nil
}


// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *CaddyOioIdwsRestWsp) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		//if !d.Args(&m.Output) {
		//	return d.ArgErr()
		//}
	}
	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Middleware.
func parseCaddyfileWsp(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m CaddyOioIdwsRestWsp
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// Interface guards
var (
	_ caddy.Provisioner              = (*CaddyOioIdwsRestWsp)(nil)
	_ caddy.Validator                = (*CaddyOioIdwsRestWsp)(nil)
	_ caddyhttp.MiddlewareHandler    = (*CaddyOioIdwsRestWsp)(nil)
	_ caddyfile.Unmarshaler          = (*CaddyOioIdwsRestWsp)(nil)
)
