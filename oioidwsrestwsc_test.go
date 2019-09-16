package oioidwsrest

import (
	"testing"
 	"gotest.tools/assert"

	"net/http"

	"net/http/httptest"

//	"crypto/x509"
	"crypto/tls"

//	"encoding/pem"
	"encoding/json"

	"strings"

	"fmt"
	"io"
	"io/ioutil"

	uuid "github.com/google/uuid"
	securityprotocol "github.com/KvalitetsIT/gosecurityprotocol"
//        stsclient "github.com/KvalitetsIT/gostsclient"
)

const test_oio_idws_rest_header_name = "sessionxyx"

func TestCallServiceWithOioIdwsRestClientWithSession(t *testing.T) {

	// Given
        subject, tokenCache := createTestOioIdwsRestHttpProtocolClient()
	req, _ := http.NewRequest("POST", "https://testservicea/test/echo", nil)
	recorder := httptest.NewRecorder()
	sessionId := uuid.New().String()
	req.Header.Add(test_oio_idws_rest_header_name, sessionId)

	// When
	httpCode, errProcess := subject.Handle(recorder, req)

	// Then
	assert.NilError(t, errProcess)
	assert.Equal(t, http.StatusOK, httpCode)

	result := recorder.Result()
	responseBody, _ := ioutil.ReadAll(result.Body)
	var jsonData map[string]interface{}
	json.Unmarshal(responseBody, &jsonData)

	headers := jsonData["headers"].(map[string]interface{})
	authorization := headers["authorization"]
	assert.Assert(t, strings.HasPrefix(fmt.Sprintf("%s", authorization), "Holder-of-key"))

	sessionIdInHeader := headers[test_oio_idws_rest_header_name]
	assert.Equal(t, sessionId, fmt.Sprintf("%s", sessionIdInHeader))

	tokenData, _ := tokenCache.FindTokenDataForSessionId(sessionId)
	assert.Equal(t, fmt.Sprintf("%s", authorization), tokenData.Authenticationtoken)
}

func TestCallServiceWithOioIdwsRestClientNoSessionId(t *testing.T) {

        // Given
        subject, _ := createTestOioIdwsRestHttpProtocolClient()
        req, _ := http.NewRequest("POST", "https://testservicea/test/echo", nil)
        recorder := httptest.NewRecorder()

        // When
        httpCode, errProcess := subject.Handle(recorder, req)

        // Then
        assert.NilError(t, errProcess)
        assert.Equal(t, http.StatusOK, httpCode)

        result := recorder.Result()
        responseBody, _ := ioutil.ReadAll(result.Body)
        var jsonData map[string]interface{}
        json.Unmarshal(responseBody, &jsonData)

        headers := jsonData["headers"].(map[string]interface{})
        authorization:= headers["authorization"]
        assert.Assert(t, strings.HasPrefix(fmt.Sprintf("%s", authorization), "Holder-of-key"))

	sessionIdInHeader := headers[test_oio_idws_rest_header_name]
        assert.Assert(t, (sessionIdInHeader == nil))
}

func createTestOioIdwsRestHttpProtocolClient() (*OioIdwsRestHttpProtocolClient, *securityprotocol.MongoTokenCache) {

	mongoTokenCache, err := securityprotocol.NewMongoTokenCache("mongo", "testwsc", "mysessions")
	if (err != nil) {
		panic(err)
	}

	mockService := new(MockService)

	config := OioIdwsRestHttpProtocolClientConfig {
		matchHandler: securityprotocol.MatchAllHandler,
		SessionHeaderName: test_oio_idws_rest_header_name,
		StsUrl: "https://sts/sts/service/sts",
		TrustCertFiles: []string { "./testgooioidwsrest/sts/sts.cer", "./testgooioidwsrest/certificates/testservicea/testservicea.cer" },
		ClientCertFile: "./testdata/medcom.cer",
		ClientKeyFile: "./testdata/medcom.pem",
		ServiceEndpoint: "https://testservicea/test",
		ServiceAudience: "urn:kit:testa:servicea",
		Service: mockService }

	testClient := NewOioIdwsRestHttpProtocolClient(config, mongoTokenCache)

	return testClient, mongoTokenCache
}
/*
func createTestStsClient() *stsclient.StsClient {

	stsUrl := "https://sts/sts/service/sts"
	stsCertFile := "./testgooioidwsrest/sts/sts.cer"
        stsCert, err := ioutil.ReadFile(stsCertFile)
	if (err != nil) {
		panic(err)
	}
        stsBlock, _ := pem.Decode([]byte(stsCert))
        stsCertToTrust, _ := x509.ParseCertificate(stsBlock.Bytes)

        stsClient, _ := stsclient.NewStsClient(stsCertToTrust, "./testdata/medcom.cer", "./testdata/medcom.pem", stsUrl)

	return stsClient
}
*/

type MockService struct {

}

func (mock *MockService) Handle(w http.ResponseWriter, r *http.Request) (int, error) {

	keyPair, err := tls.LoadX509KeyPair("./testdata/medcom.cer", "./testdata/medcom.pem")
        if (err != nil) {
		panic(err)
        }

	config := &tls.Config{
		Certificates: []tls.Certificate{ keyPair },
		InsecureSkipVerify: true,
	}
	tr := &http.Transport{ TLSClientConfig: config }
	client := &http.Client{ Transport: tr }

	resp, err := client.Do(r)
	if (err != nil) {
		return http.StatusInternalServerError, err
	}

	w.WriteHeader(http.StatusOK)
	io.Copy(w, resp.Body)
	resp.Body.Close()

	return resp.StatusCode, nil
}
