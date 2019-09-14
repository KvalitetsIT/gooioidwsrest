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
//        audience := "urn:kit:testa:servicea"

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

	sessionIdHandler := securityprotocol.HttpHeaderSessionIdHandler{ HttpHeaderName: test_oio_idws_rest_header_name }

	mockService := new(MockService)

	stsClient := createTestStsClient()

	testClient := NewOioIdwsRestHttpProtocolClient(securityprotocol.MatchAllHandler, mongoTokenCache, sessionIdHandler, nil, stsClient, mockService)

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
