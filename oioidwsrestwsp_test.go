package oioidwsrest

import (
	"fmt"
	"strings"
	"testing"
 	"gotest.tools/assert"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"io/ioutil"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"encoding/base64"
	securityprotocol "github.com/KvalitetsIT/gosecurityprotocol"
	saml2 "github.com/russellhaering/gosaml2/types"
	"go.uber.org/zap"
	"time"
)


func TestCallWspServerWithoutClientSSLCertifikatFails(t *testing.T) {

	// Given
	config := createConfig()
	httpServer, _ := createOioIdwsWsp(config, nil, nil)
	httpClient := httpServer.Client()

	// When
	res, _ := httpClient.Get(httpServer.URL)

	// Then
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
}

func TestCallWspWithClientSSLCertificateButWithoutAuthenticationTokenFails(t *testing.T) {

        // Given
        config := createConfig()
        httpServer, _ := createOioIdwsWsp(config, nil, mockClientCertificate)
	httpClient := httpServer.Client()

        // When
        res, _ := httpClient.Get(httpServer.URL)

        // Then
        assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
}

/**
  * In this testcase we use one SSL client certificate in communicating with the STS and 
  * then try to authenticate on the service provider by using a difference SSL client
  * certificate which should fail
  */
func TestThatHokIsValidatedOnAuthentication(t *testing.T) {
        // Given
        config := createConfig()
        httpServer, wsp := createOioIdwsWsp(config, createMongoSessionCache(), mockClientCertificate)
        httpClient := httpServer.Client()
        wsc, _ := CreateTestOioIdwsRestHttpProtocolClient()
        encodedToken, _ := wsc.GetEncodedTokenFromSts([]byte{}, nil)
        authRequest := fmt.Sprintf("saml-token=%s", encodedToken)
        authUrl := fmt.Sprintf("%s/token", httpServer.URL)

        // When
	wsp.ClientCertHandler = mockHijackerCertificate
        authResp, _ := httpClient.Post(authUrl, "any", strings.NewReader(authRequest))

        // Then
        assert.Equal(t, http.StatusUnauthorized, authResp.StatusCode)
}

/**
  * In this testcase we verify that HoK session cannot be highjacked. We start by authenticating
  * and then trying to use the authentication token but with a different SSL client certificate
  * which should fail
  */
func TestThatAuthenticatedSessionCannotBeHijackedBecauseOfHoKValidation(t *testing.T) {
        // Given
        config := createConfig()
        httpServer, wsp := createOioIdwsWsp(config, createMongoSessionCache(), mockClientCertificate)
        httpClient := httpServer.Client()
        wsc, _ := CreateTestOioIdwsRestHttpProtocolClient()
        encodedToken, _ := wsc.GetEncodedTokenFromSts([]byte{}, nil)
        authRequest := fmt.Sprintf("saml-token=%s", encodedToken)
        authUrl := fmt.Sprintf("%s/token", httpServer.URL)
        serviceUrl := fmt.Sprintf("%s/hello", httpServer.URL)

        // When
        authResp, authErr := httpClient.Post(authUrl, "any", strings.NewReader(authRequest))
        oioIdwsRestAuth, authParseErr := CreateOioIdwsRestAuthResponseFromHttpReponse(authResp,zap.NewNop().Sugar())
	wsp.ClientCertHandler = mockHijackerCertificate
        serviceRequest := createServiceRequest(serviceUrl, oioIdwsRestAuth)
        serviceResp, serviceErr := httpClient.Do(serviceRequest)

        // Then
        assert.NilError(t, authErr)
        assert.NilError(t, authParseErr)
        assert.NilError(t, serviceErr)

        assert.Equal(t, http.StatusOK, authResp.StatusCode)
        assert.Equal(t, "Holder-of-key", oioIdwsRestAuth.TokenType)
        assert.Assert(t, oioIdwsRestAuth.ExpiresIn > 0)
        assert.Assert(t, len(oioIdwsRestAuth.AccessToken) > 0)

        assert.Equal(t, http.StatusUnauthorized, serviceResp.StatusCode)
}

/**
  * In this testcase we try to authenticate on the service provider with a token
  * from the STS where the audience restriction is different from the audience
  * required by the service provider which should fail
  */
func TestThatAuthenticationFailsIfAudienceDoesNotMatch(t *testing.T) {

        // Given
        config := createConfig()
	config.AudienceRestriction = "urn:no:match:for:me"
        httpServer, _ := createOioIdwsWsp(config, createMongoSessionCache(), mockClientCertificate)
        httpClient := httpServer.Client()
        wsc, _ := CreateTestOioIdwsRestHttpProtocolClient()
        encodedToken, _ := wsc.GetEncodedTokenFromSts([]byte{}, nil)
        authRequest := fmt.Sprintf("saml-token=%s", encodedToken)
        authUrl := fmt.Sprintf("%s/token", httpServer.URL)

        // When
        authResp, authErr := httpClient.Post(authUrl, "any", strings.NewReader(authRequest))

        // Then
        assert.NilError(t, authErr)
	assert.Equal(t, http.StatusUnauthorized, authResp.StatusCode)
}


/**
  * Test that the audience is not validated on the service provider if 
  * the configuration of the service provider does not require this
  */
func TestThatAudienceIsNotMatchedIfNotInConfig(t *testing.T) {

        // Given
        config := createConfig()
        config.AudienceRestriction = "" // Means no audience check!!
        httpServer, _ := createOioIdwsWsp(config, createMongoSessionCache(), mockClientCertificate)
        httpClient := httpServer.Client()
        wsc, _ := CreateTestOioIdwsRestHttpProtocolClient()
        encodedToken, _ := wsc.GetEncodedTokenFromSts([]byte{}, nil)
        authRequest := fmt.Sprintf("saml-token=%s", encodedToken)
        authUrl := fmt.Sprintf("%s/token", httpServer.URL)

        // When
        authResp, authErr := httpClient.Post(authUrl, "any", strings.NewReader(authRequest))

        // Then
        assert.NilError(t, authErr)
        assert.Equal(t, http.StatusOK, authResp.StatusCode)
}

/**
  * Sunshine scenario in which the authentication is successful and service calls are possible
  */
func TestAuthenticateAndCallingServiceUsingLegalTokenAndClientCertificate(t *testing.T) {

	// Given
        config := createConfig()
        httpServer, _ := createOioIdwsWsp(config, createMongoSessionCache(), mockClientCertificate)
        httpClient := httpServer.Client()
	wsc, _ := CreateTestOioIdwsRestHttpProtocolClient()
	encodedToken, _ := wsc.GetEncodedTokenFromSts([]byte{}, nil)
	time.Sleep(2000) // Just to check that the timestamps are set correctly in the session
	authRequest := fmt.Sprintf("saml-token=%s", encodedToken)
	authUrl := fmt.Sprintf("%s/token", httpServer.URL)
	serviceUrl := fmt.Sprintf("%s/hello", httpServer.URL)
	sessionDataUrl := fmt.Sprintf("%s/getsessiondata", httpServer.URL)

	// When
	authResp, authErr := httpClient.Post(authUrl, "any", strings.NewReader(authRequest))
	oioIdwsRestAuth, authParseErr := CreateOioIdwsRestAuthResponseFromHttpReponse(authResp,zap.NewNop().Sugar())
	serviceRequest := createServiceRequest(serviceUrl, oioIdwsRestAuth)
	serviceResp, serviceErr := httpClient.Do(serviceRequest)
	sessionDataResp, sessionDataErr := httpClient.Do(createServiceRequest(sessionDataUrl, oioIdwsRestAuth))

	// Then
	assert.NilError(t, authErr)
	assert.NilError(t, authParseErr)
	assert.NilError(t, serviceErr)
	assert.NilError(t, sessionDataErr)

	assert.Equal(t, http.StatusOK, authResp.StatusCode)
	assert.Equal(t, "Holder-of-key", oioIdwsRestAuth.TokenType)
	assert.Assert(t, oioIdwsRestAuth.ExpiresIn > 0)
	assert.Assert(t, len(oioIdwsRestAuth.AccessToken) > 0)

	assert.Equal(t, http.StatusTeapot, serviceResp.StatusCode)
	assert.Equal(t, http.StatusOK, sessionDataResp.StatusCode)

	getSessionDataBody, _ := ioutil.ReadAll(sessionDataResp.Body)
        var jsonData map[string]interface{}
        unMarshalErr := json.Unmarshal(getSessionDataBody, &jsonData)
	assert.NilError(t, unMarshalErr)

	// Check UserAttributes
	userAttributesValue, containsUserAttributes := jsonData["UserAttributes"]
	assert.Assert(t, containsUserAttributes, "Expected 'UserAttributes' to be present in the sessiondata")
	userAttributes, userAttributesMapOk := userAttributesValue.(map[string]interface{})
	assert.Assert(t, userAttributesMapOk, "Expected the 'UserAttributes' to be a map")
	assert.Equal(t, 2, len(userAttributes), "Expected number of keys in 'UserAttributes' map")
	testTestValue, containsTestTest := userAttributes["test:test"]
	assert.Assert(t, containsTestTest)
	testTest, testTestOk := testTestValue.([]interface{})
	assert.Assert(t, testTestOk, "Expected the 'UserAttributes[test:test]' to be an array")
	assert.Equal(t, 2, len(testTest))
	assert.Equal(t, "autovalue1", testTest[0])
	assert.Equal(t, "autovalue2", testTest[1])

	// Check Authenticationtoken
	authenticationTokenBase64ValueJson, containsAuthenticationToken := jsonData["Authenticationtoken"]
	authenticationTokenBase64Value, _ := authenticationTokenBase64ValueJson.(string)
	assert.Assert(t, containsAuthenticationToken, "Expected the sessiondata to contain 'Authenticationtoken'")
	authenticationTokenValue, errAuthenticationTokenDecode := base64.StdEncoding.DecodeString(authenticationTokenBase64Value)
	assert.NilError(t, errAuthenticationTokenDecode, "Expected the 'Authenticationtoken' to be in base64 format")
	var assertion saml2.Assertion
        errAssertionUnmarshal := xml.Unmarshal([]byte(authenticationTokenValue), &assertion)
	assert.NilError(t, errAssertionUnmarshal, "Expected the base64 decoded 'Authenticationtoken' from the sessiondata to be a parsable SAML assertion")

	// Check Timestamp/expiry
	sessionDataTimestamp, sessionDataTimestampParseErr := time.Parse(time.RFC3339, (jsonData["Timestamp"]).(string))
        assert.NilError(t, sessionDataTimestampParseErr, "Expected the 'Timestamp' from the sessiondata to be a parsable timestamp")
	notAfterDateFromAssertion, notAfterDateParseErr := time.Parse(time.RFC3339, assertion.Conditions.NotOnOrAfter)
	assert.NilError(t, notAfterDateParseErr, "Expected the 'NotOnOrAfter' from the SAML assertion to be a parsable timestamp")
	assert.Equal(t, sessionDataTimestamp, notAfterDateFromAssertion, "Expected the session timeout and the notAfterDate from the SAML assertion to match")
}




/**
  *
  *  UTILITES til testen
  *
  */
func createConfig() *OioIdwsRestHttpProtocolServerConfig {

	c := new(OioIdwsRestHttpProtocolServerConfig)
	c.TrustCertFiles = []string { "./testgooioidwsrest/sts/sts.cer" }
	c.Service = new(mockService)
	c.AudienceRestriction = "urn:kit:testa:servicea"
	c.HoK = true
        return c
}

type mockService struct {
}

func (m mockService) Handle(http.ResponseWriter, *http.Request) (int, error) {

	return http.StatusTeapot, nil
}

func createServiceRequest(serviceUrl string, oioAuth *OioIdwsRestAuthResponse) *http.Request {

	request, _ := http.NewRequest("GET", serviceUrl, nil)
	authorizationValue := fmt.Sprintf("%s %s", oioAuth.TokenType, oioAuth.AccessToken)
	request.Header.Set("Authorization", authorizationValue)
	return request
}

func mockClientCertificate(req *http.Request) *x509.Certificate  {
	return readCertificate("./testdata/medcom.cer")
}

func mockHijackerCertificate(req *http.Request) *x509.Certificate  {
        return readCertificate("./testdata/other.cer")
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

func createOioIdwsWsp(config *OioIdwsRestHttpProtocolServerConfig, sessionCache securityprotocol.SessionCache, clientCertHandler func(*http.Request) *x509.Certificate) (*httptest.Server, *OioIdwsRestWsp) {

	wsp := NewOioIdwsRestWspFromConfig(config, sessionCache, zap.NewNop().Sugar())
	if (clientCertHandler != nil) {
		wsp.ClientCertHandler = clientCertHandler
	}

	// Bridge the test server and the wsp
	handler := func(w http.ResponseWriter, r *http.Request) {
		responseCode, err := wsp.Handle(w, r)
		w.WriteHeader(responseCode)
		if (err != nil) {
			w.Write([]byte(err.Error()))
		}
	}

	return createTlsServer(handler), wsp
}


func createTlsServer(handlerFunc func(http.ResponseWriter, *http.Request)) *httptest.Server {

	ts := httptest.NewTLSServer(http.HandlerFunc(handlerFunc))
	return ts
}

