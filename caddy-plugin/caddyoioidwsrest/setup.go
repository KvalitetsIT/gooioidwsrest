package caddyoioidwsrest

import (
        "net/http"
        "crypto/tls"

	"fmt"
	"os"
	"strconv"
	"oioidwsrest"
	securityprotocol "github.com/KvalitetsIT/gosecurityprotocol"
	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

const CONFIG_MONGO_DB = "mongo_db"
const CONFIG_SESSION_HEADER_NAME = "session_header_name"
const CONFIG_SESSION_DATA_URL = "session_data_url"
const CONFIG_STS_URL = "sts_url"
const CONFIG_TRUST_CERT_FILES = "trust_cert_files"
const CONFIG_CLIENT_CERT_FILE = "client_cert_file"
const CONFIG_CLIENT_KEY_FILE = "client_key_file"
const CONFIG_SERVICE_AUDIENCE = "service_audience"
const CONFIG_SERVICE_ENDPOINT = "service_endpoint"


const DEFAULT_VALUE_SESSION_HEADER_NAME = "SESSION"


func init() {
	// Siemens Proxy
	caddy.RegisterPlugin("oioidwsrestwsc", caddy.Plugin{
		ServerType: "http",
		Action:     setupWsc,
	})
	httpserver.RegisterDevDirective("oioidwsrestwsc", "header")
}


func getMongoSettings() (string) {
        // Reading mongo settings from ENV
        mongo_host := readPropertyFromEnvironment(false, "mongo_host", "")

        mongo_port := os.Getenv("mongo_port")
        if (len(mongo_port) == 0) {
                mongo_port = "27017"
        }
        _, conv_err := strconv.Atoi(mongo_port)
        if (conv_err != nil) {
                panic(conv_err)
        }

	mongo_url := fmt.Sprintf("%s:%s", mongo_host, mongo_port)
	return mongo_url
}


func setupWsc(c *caddy.Controller) error {

	wscConfig, tokenCache, err := parseWscConfig(c)
	if (err != nil) {
		panic(err)
	}


	// Configuring the handler from the configuration
	cfg := httpserver.GetConfig(c)

	mid := func(next httpserver.Handler) httpserver.Handler {


		caddyHandler, err := NewOioIdwsRestWsdCaddyHandler(tokenCache, wscConfig, next)
		if (err != nil) {
			panic(err)
		}

		return caddyHandler
	}
	cfg.AddMiddleware(mid)

	return nil
}

func readMandatoryPropertyFromEnvironment(envVariableName string) string {
	return readPropertyFromEnvironment(false, envVariableName, "")
}

func readPropertyFromEnvironment(optional bool, envVariableName string, defaultValue string) string {

	value := os.Getenv(envVariableName)
        if (len(value) == 0) {
		if (!optional && len(defaultValue) == 0) {
			panic(fmt.Sprintf("The %s env variable must be set", envVariableName))
		}
		return defaultValue
        }
	return value
}

func parseWscConfig(c *caddy.Controller) (*oioidwsrest.OioIdwsRestHttpProtocolClientConfig, *securityprotocol.MongoTokenCache, error) {

       	mongo_url := getMongoSettings()

	var tokenCache *securityprotocol.MongoTokenCache
	sessionDataUrl := ""

	wscConfig := new(oioidwsrest.OioIdwsRestHttpProtocolClientConfig)
	wscConfig.SessionHeaderName = DEFAULT_VALUE_SESSION_HEADER_NAME
	wscConfig.SessionDataFetcher = new(securityprotocol.NilSessionDataFetcher)

	// This parses the following config blocks
	/*
		oioidwsrestwsc {

			mongo_db wscdb

			session_header_name SESSION_XYZ

			sts_url https://sts.dk/kuk
                        trust_cert_files /trust/certa.cer /trust/certb.cer

			client_cert_file /cert/client.cer
			client_key_file /cert/client.key

			service_audience uri:audience:servicea
			service_endpoint https://services.com/servicea

		}
	*/

	for c.Next() {
		args := c.RemainingArgs()
		switch len(args) {
		case 0:
			// no argument passed, check the config block
			for c.NextBlock() {
				switch c.Val() {
                                case CONFIG_MONGO_DB:
                                        if !c.NextArg() {
                                                return nil, nil, c.ArgErr()
                                        }
                                       	mongoDb := c.Val()

					tc, err := securityprotocol.NewMongoTokenCache(mongo_url, mongoDb, "wscsessions")
					if (err != nil) {
						return nil, nil, err
					}
					tokenCache = tc
                                        if c.NextArg() {
                                                // only one mongodb per declaration
                                                return nil, nil, c.ArgErr()
                                        }
				case CONFIG_SESSION_HEADER_NAME:
					if !c.NextArg() {
                                                return nil, nil, c.ArgErr()
                                        }
                                        wscConfig.SessionHeaderName = c.Val()
					if c.NextArg() {
                                                // only one session header name per declaration
                                                return nil, nil, c.ArgErr()
                                        }
				case CONFIG_STS_URL:
                                       if !c.NextArg() {
                                                return nil, nil, c.ArgErr()
                                        }
                                        wscConfig.StsUrl = c.Val()
                                        if c.NextArg() {
                                                // only one stsurl per declaration
                                                return nil, nil, c.ArgErr()
                                        }
				case CONFIG_TRUST_CERT_FILES:
                                       for (c.NextArg()) {
                                                wscConfig.TrustCertFiles = append(wscConfig.TrustCertFiles, c.Val())
                                        }
                               	case CONFIG_CLIENT_CERT_FILE:
                                       if !c.NextArg() {
                                                return nil, nil, c.ArgErr()
                                        }
                                        wscConfig.ClientCertFile = c.Val()
                                        if c.NextArg() {
                                                // only one client cert per declaration
                                                return nil, nil, c.ArgErr()
                                        }
                                case CONFIG_CLIENT_KEY_FILE:
                                       if !c.NextArg() {
                                                return nil, nil, c.ArgErr()
                                        }
                                        wscConfig.ClientKeyFile = c.Val()
                                        if c.NextArg() {
                                                // only one client cert per declaration
                                                return nil, nil, c.ArgErr()
                                        }
                                case CONFIG_SERVICE_AUDIENCE:
                                       if !c.NextArg() {
                                                return nil, nil, c.ArgErr()
                                        }
                                        wscConfig.ServiceAudience = c.Val()
                                        if c.NextArg() {
                                                // only one audience per declaration
                                                return nil, nil, c.ArgErr()
                                        }
				case CONFIG_SESSION_DATA_URL:
					if !c.NextArg() {
                                                return nil, nil, c.ArgErr()
                                        }
                                        sessionDataUrl = c.Val()
                                        if c.NextArg() {
                                                // only one session_data_url per declaration
                                                return nil, nil, c.ArgErr()
                                        }
                                case CONFIG_SERVICE_ENDPOINT:
                                       if !c.NextArg() {
                                                return nil, nil, c.ArgErr()
                                        }
                                        wscConfig.ServiceEndpoint = c.Val()
                                        if c.NextArg() {
                                                // only one serviceendpoint per declaration
                                                return nil, nil, c.ArgErr()
                                        }
                                }

			}
		default:
			// we want no arguments
			return nil, nil, c.ArgErr()
		}
	}

	// Check mandatory values
	if (len(wscConfig.StsUrl) == 0) {
		return nil, nil, fmt.Errorf("sts_url must be set")
	}
	if (len(wscConfig.ClientCertFile) == 0) {
		return nil, nil, fmt.Errorf("client_cert_file must be set")
	}
        if (len(wscConfig.ClientKeyFile) == 0) {
                return nil, nil, fmt.Errorf("client_key_file must be set")
        }
        if (len(wscConfig.ServiceAudience) == 0) {
                return nil, nil, fmt.Errorf("service_audience must be set")
        }
        if (len(wscConfig.ServiceEndpoint) == 0) {
                return nil, nil, fmt.Errorf("service_endpoint must be set")
        }
	if (len(sessionDataUrl) > 0) {

		caCertPool := oioidwsrest.CreateCaCertPool(wscConfig.TrustCertFiles)
		tlsConfig := &tls.Config{
                	RootCAs:      caCertPool,
		}
        	transport := &http.Transport{TLSClientConfig: tlsConfig}
        	client := &http.Client{Transport: transport}

		wscConfig.SessionDataFetcher = securityprotocol.NewServiceCallSessionDataFetcher(sessionDataUrl, client)
	}

	if (tokenCache == nil) {
		return nil, nil, fmt.Errorf(fmt.Sprintf("%s must be set", CONFIG_MONGO_DB))
	}

	return wscConfig, tokenCache, nil
}
