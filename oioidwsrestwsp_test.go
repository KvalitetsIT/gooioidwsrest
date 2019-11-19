package oioidwsrest

import (
	"strings"
	"testing"
 	"gotest.tools/assert"
	"fmt"
	"net/http"
	"net/http/httptest"
	"io/ioutil"
	"crypto/x509"
	"encoding/pem"
	securityprotocol "github.com/KvalitetsIT/gosecurityprotocol"
)


func TestCallWspServerWithoutClientSSLCertifikatFails(t *testing.T) {

	// Given
	config := createConfig()
	httpServer := createOioIdwsWsp(config, nil, nil)
	httpClient := httpServer.Client()

	// When
	res, _ := httpClient.Get(httpServer.URL)

	// Then
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
}


func TestCallWspWithClientSSLCertificateButWithoutAuthenticationTokenFails(t *testing.T) {

        // Given
        config := createConfig()
        httpServer := createOioIdwsWsp(config, nil, mockClientCertificate)
	httpClient := httpServer.Client()

        // When
        res, _ := httpClient.Get(httpServer.URL)

        // Then
        assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
}


func TestAuthenticateUsingLegalTokenAndClientCertificate(t *testing.T) {

	// Given
        config := createConfig()
        httpServer := createOioIdwsWsp(config, createMongoSessionCache(), mockClientCertificate)
        httpClient := httpServer.Client()
	wsc, _ := CreateTestOioIdwsRestHttpProtocolClient()
	encodedToken, _ := wsc.GetEncodedTokenFromSts([]byte{}, nil)
	tokenRequest := fmt.Sprintf("saml-token=%s", encodedToken)
	authUrl := fmt.Sprintf("%s/token", httpServer.URL)
	fmt.Println(authUrl)

	// When
	res, authErr := httpClient.Post(authUrl, "any", strings.NewReader(tokenRequest))
	oioIdwsRestAuth, authParseErr := CreateOioIdwsRestAuthResponseFromHttpReponse(res)

	// Then


	assert.NilError(t, authErr)
	assert.NilError(t, authParseErr)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, "Holder-of-key", oioIdwsRestAuth.TokenType)
	assert.Assert(t, oioIdwsRestAuth.ExpiresIn > 0)
	assert.Assert(t, len(oioIdwsRestAuth.AccessToken) > 0)
}




/**
  *
  *  UTILITES til testen
  *
  */
func createConfig() *OioIdwsRestHttpProtocolServerConfig {

	c := new(OioIdwsRestHttpProtocolServerConfig)
	c.TrustCertFiles = []string { "./testgooioidwsrest/sts/sts.cer" }
//	c.Service =
//	c.AudienceRestriction =
        return c
}

func mockClientCertificate(req *http.Request) *x509.Certificate  {
	return readCertificate("./testdata/medcom.cer")
}

func readCertificate(filename string) *x509.Certificate  {
        cert, _ := ioutil.ReadFile(filename)
        certBlock, _ := pem.Decode([]byte(cert))
        res, _ := x509.ParseCertificate(certBlock.Bytes)
        return res
}

func createMongoSessionCache() securityprotocol.SessionCache {

	res, _ := securityprotocol.NewMongoSessionCache("mongo", "wsp", "sessions")
	return res
}

func createOioIdwsWsp(config *OioIdwsRestHttpProtocolServerConfig, sessionCache securityprotocol.SessionCache, clientCertHandler func(*http.Request) *x509.Certificate) *httptest.Server {

	wsp := NewOioIdwsRestWspFromConfig(config, sessionCache)
	if (clientCertHandler != nil) {
		wsp.ClientCertHandler = clientCertHandler
	}

	// Bridge the test server and the wsp
	handler := func(w http.ResponseWriter, r *http.Request) {
		responseCode, err := wsp.Handle(w, r)
		w.WriteHeader(responseCode)
		if (err != nil) {
			w.Write([]byte(err.Error()))
		} else {
			fmt.Println("FEEEEEEEEEEEEEEEEEEEEEEEEEJL")
		}
	}

	return createTlsServer(handler)
}


func createTlsServer(handlerFunc func(http.ResponseWriter, *http.Request)) *httptest.Server {

	ts := httptest.NewTLSServer(http.HandlerFunc(handlerFunc))
	return ts
}

