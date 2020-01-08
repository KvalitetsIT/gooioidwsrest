package oioidwsrest

import (
        "net/http"
	"io"
	"fmt"
	"encoding/json"
	"io/ioutil"
	"time"
	securityprotocol "github.com/KvalitetsIT/gosecurityprotocol"
	"go.uber.org/zap"
)

const OIO_IDWS_REST_TOKEN_TYPE_HOLDER_OF_KEY = "Holder-of-key"
const OIO_IDWS_REST_TOKEN_TYPE_BEARER = "Bearer"


type OioIdwsRestAuthResponse struct {

	AccessToken	string	`json:"access_token"`
	TokenType	string  `json:"token_type"`
	ExpiresIn	int64	`json:"expires_in"`
}

func CreateOioIdwsRestAuthResponseFromHttpReponse(authResponse *http.Response, logger *zap.SugaredLogger) (*OioIdwsRestAuthResponse, error) {
        if (authResponse.StatusCode != http.StatusOK) {
            logger.Warnf("Authentication failed with statusCode: %d", authResponse.StatusCode)
            return nil, fmt.Errorf(fmt.Sprintf("Authentication failed with statusCode: %d", authResponse.StatusCode))
        }
        responseBody, err := ioutil.ReadAll(authResponse.Body)
        if (err != nil) {
           logger.Warnf("Cannot read responseBody: %v", err)
           return nil, err
        }

        var jsonResponse OioIdwsRestAuthResponse
        err = json.Unmarshal([]byte(responseBody), &jsonResponse)
        if (err != nil) {
           logger.Warnf("Cannot unmarshal body: %v",err)
           return nil, err
        }
        return &jsonResponse, nil
}

func CreateAuthenticatonRequestInfoFromReponse(authResponse *http.Response, logger *zap.SugaredLogger) (*OioIdwsRestAuthenticationInfo, error) {
	jsonResponse, err := CreateOioIdwsRestAuthResponseFromHttpReponse(authResponse,logger)
	if (err != nil) {
		return nil, err
	}
    return &OioIdwsRestAuthenticationInfo{ Token: fmt.Sprintf("%s %s", jsonResponse.TokenType, jsonResponse.AccessToken), ExpiresIn: jsonResponse.ExpiresIn }, nil
}

func ResponseWithSuccessfulAuth(w http.ResponseWriter, sessionData *securityprotocol.SessionData) (int, error) {

	// Create authentication payload from sessiondata
	authResponsePayload := OioIdwsRestAuthResponse {
		AccessToken: sessionData.Sessionid,
		TokenType: calculateTokenType(sessionData),
		ExpiresIn: getExpiresInFromExpiryTimeStamp(sessionData.Timestamp),
	}

	// Serialize the authentication payload and write it to the response
	payload, err := json.Marshal(authResponsePayload)
	if (err != nil) {
		return http.StatusUnauthorized, err
	}
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, string(payload))

	return http.StatusOK, nil
}

func getExpiresInFromExpiryTimeStamp(timestamp time.Time) int64 {

	return	int64(timestamp.Sub(time.Now()).Seconds())
}

func calculateTokenType(sessionData *securityprotocol.SessionData) string {
	if (sessionData.ClientCertHash == "") {
		return OIO_IDWS_REST_TOKEN_TYPE_BEARER
	} 
	return OIO_IDWS_REST_TOKEN_TYPE_HOLDER_OF_KEY
}
