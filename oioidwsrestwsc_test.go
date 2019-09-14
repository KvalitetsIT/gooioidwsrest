package oioidwsrest

import (
	"testing"
 	"gotest.tools/assert"

	"net/http"

	"crypto/tls"
	"crypto/x509"

	"encoding/pem"

	"io/ioutil"

	securityprotocol "github.com/KvalitetsIT/gosecurityprotocol"
        stsclient "github.com/KvalitetsIT/gostsclient"
)

const test_oio_idws_rest_header_name = "sessionxyx"

func TestCallServiceWithOioIdwsRestClient(t *testing.T) {

	// Given
        subject := createTestOioIdwsRestHttpProtocolClient()
	req, _ := http.NewRequest("GET", "/someurl", nil)

	// When
	httpCode, errProcess := subject.Handle(nil, req)

	// Then
	assert.NilError(t, errProcess)
	assert.Equal(t, http.StatusOK, httpCode)

	//assert.Equal(t, authAssertion.assertion.Version, "2.0")
	//assert.Equal(t, len(authAssertion.assertion.AttributeStatement.Attributes), 4)
	// TODO: tjek flere
}

func createTestOioIdwsRestHttpProtocolClient() *OioIdwsRestHttpProtocolClient {

	mongoTokenCache, err := securityprotocol.NewMongoTokenCache("mongo", "testwsc", "mysessions")
	if (err != nil) {
		panic(err)
	}

	mockService := new(MockService)

	config := OioIdwsRestHttpProtocolClientConfig {
		matchHandler: securityprotocol.MatchAllHandler,
		SessionHeaderName: test_oio_idws_rest_header_name,
		StsUrl: "https://sts/sts/service/sts",
		StsCertFile: "./testgooioidwsrest/sts/sts.cer",
		ClientCertFile: "./testdata/medcom.cer",
		ClientKeyFile: "./testdata/medcom.pem",
		ServiceEndpoint: "https://service",
		ServiceAudience: "urn:kit:testa:servicea",
		Service: mockService }

	testClient := NewOioIdwsRestHttpProtocolClient(config, mongoTokenCache)

	return testClient
}

func createTestStsClient() *stsclient.StsClient {

	stsUrl := "https://sts/sts/service/sts"
	stsCertFile := "./testgooioidwsrest/sts/sts.cer"
        stsCert, err := ioutil.ReadFile(stsCertFile)
	if (err != nil) {
		panic(err)
	}
        stsBlock, _ := pem.Decode([]byte(stsCert))
        stsCertToTrust, _ := x509.ParseCertificate(stsBlock.Bytes)

        clientKeyPair, _ := tls.LoadX509KeyPair("./testdata/medcom.cer", "./testdata/medcom.pem")
        stsClient, _ := stsclient.NewStsClient(stsCertToTrust, &clientKeyPair, stsUrl)

	return stsClient
}


type MockService struct {

}

func (mock *MockService) Handle(http.ResponseWriter, *http.Request) (int, error) {
        return http.StatusOK, nil
}
