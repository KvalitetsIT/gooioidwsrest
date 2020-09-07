package oioidwsrest

import (
	"testing"
 	"gotest.tools/assert"

	"net/http"

	"net/http/httptest"

	"crypto/tls"

	"encoding/json"
	"encoding/base64"

	"strings"

	"fmt"
	"io"
	"io/ioutil"

	uuid "github.com/google/uuid"
	securityprotocol "github.com/KvalitetsIT/gosecurityprotocol"

	"go.uber.org/zap"
)

const test_oio_idws_rest_header_name = "sessionxyx"

func TestCallServiceWithOioIdwsRestClientWithSessionIdNoSessionDataHandler(t *testing.T) {

	// Given
	subject, tokenCache := CreateTestOioIdwsRestHttpProtocolClient(nil)
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

func TestCallServiceWithOioIdwsRestClientWithSessionIdAndExtraClaimsNoSessionDataHandler(t *testing.T) {

	// Given
        subject, tokenCache := CreateTestOioIdwsRestHttpProtocolClient(nil)
	req, _ := http.NewRequest("POST", "https://testservicea/test/echo", nil)
        claimName := "claim-b"
        claimValue := "myclaimvalue1234"
	claims := []Claim { Claim{ Key: claimName, Value: claimValue } }
	claimBytes, _ := json.Marshal(claims)
	claimBytesEncoded := base64.URLEncoding.EncodeToString(claimBytes)
	recorder := httptest.NewRecorder()
	sessionId := uuid.New().String()
	req.Header.Add(test_oio_idws_rest_header_name, sessionId)
	req.Header.Add(HTTP_HEADER_X_CLAIMS, claimBytesEncoded)

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

        sessionDataFromWsp, err := getSessionDataFromWsp(fmt.Sprintf("%s", headers["session"]))
        assert.NilError(t, err)
        assert.Assert(t, (sessionDataFromWsp != nil))
        userAttributeClaimBValues := sessionDataFromWsp.UserAttributes[claimName]
        assert.Equal(t, 1, len(userAttributeClaimBValues))
        assert.Equal(t, claimValue, userAttributeClaimBValues[0])
}


func TestCallServiceWithOioIdwsRestClientWithSessionIdAndSessionDataHandlerWithClaims(t *testing.T) {

        // Given
	sessionAttributes := make(map[string]string)
	sessionAttributeClaimName := "claim-b"
	sessionAttributeClaimValue := "myclaimvalue1234"
	sessionAttributes[sessionAttributeClaimName] = sessionAttributeClaimValue

	mockSessionDataFetcher := MockSessionDataFetcher{ sessionData: securityprotocol.SessionData{ SessionAttributes: sessionAttributes } }

        subject, tokenCache := CreateTestOioIdwsRestHttpProtocolClient(mockSessionDataFetcher)
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

	sessionDataFromWsp, err := getSessionDataFromWsp(fmt.Sprintf("%s", headers["session"]))
	assert.NilError(t, err)
        assert.Assert(t, (sessionDataFromWsp != nil))
	userAttributeClaimBValues := sessionDataFromWsp.UserAttributes[sessionAttributeClaimName]
	assert.Equal(t, 1, len(userAttributeClaimBValues))
	assert.Equal(t, sessionAttributeClaimValue, userAttributeClaimBValues[0])
}


func TestCallServiceWithOioIdwsRestClientNoSessionIdNoSessionDataHandler(t *testing.T) {

        // Given
        subject, _ := CreateTestOioIdwsRestHttpProtocolClient(new(securityprotocol.NilSessionDataFetcher))
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


/**
  *
  *  UTILITES til testen
  *
  */
func CreateTestOioIdwsRestHttpProtocolClientIssuer1() (*OioIdwsRestHttpProtocolClient, *securityprotocol.MongoTokenCache) {

        return createTestOioIdwsRestHttpProtocolClient(new(securityprotocol.NilSessionDataFetcher), "./testdata/issued2.cer", "./testdata/issued2.key")
}

func CreateTestOioIdwsRestHttpProtocolClient(sessionDataFetcher securityprotocol.SessionDataFetcher) (*OioIdwsRestHttpProtocolClient, *securityprotocol.MongoTokenCache) {

	return createTestOioIdwsRestHttpProtocolClient(sessionDataFetcher, "./testdata/medcom.cer", "./testdata/medcom.pem")
}

func createTestOioIdwsRestHttpProtocolClient(sessionDataFetcher securityprotocol.SessionDataFetcher, clientCertFile string, clientKeyFile string) (*OioIdwsRestHttpProtocolClient, *securityprotocol.MongoTokenCache) {

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
		ClientCertFile: clientCertFile,
		ClientKeyFile: clientKeyFile,
		SessionDataFetcher: sessionDataFetcher,
		ServiceEndpoint: "https://testservicea/test",
		ServiceAudience: "urn:kit:testa:servicea",
		Service: mockService }

	testClient := NewOioIdwsRestHttpProtocolClient(config, mongoTokenCache, zap.NewNop().Sugar() )

	return testClient, mongoTokenCache
}


func getSessionDataFromWsp(wspSessionId string) (*securityprotocol.SessionData, error) {

      wspSessionDataFetcher := securityprotocol.NewServiceCallSessionDataFetcher("http://testservicea", &http.Client{})
      sessionIdHandler := securityprotocol.HttpHeaderSessionIdHandler{ HttpHeaderName: "session" }
      return wspSessionDataFetcher.GetSessionData(wspSessionId, sessionIdHandler)
}

type MockSessionDataFetcher struct {

	sessionData	securityprotocol.SessionData
}

func (mock MockSessionDataFetcher) GetSessionData(string, securityprotocol.SessionIdHandler) (*securityprotocol.SessionData, error) {

	return &mock.sessionData, nil
}


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
