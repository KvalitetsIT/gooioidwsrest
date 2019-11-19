package oioidwsrest

import (
        "net/http"
	"fmt"
	"log"
	"encoding/json"
	"io/ioutil"
)


type OioIdwsRestAuthResponse struct {

	AccessToken	string	`json:"access_token"`
	TokenType	string  `json:"token_type"`
	ExpiresIn	int64	`json:"expires_in"`
}

func CreateAuthenticatonRequestInfoFromReponse(authResponse *http.Response) (*OioIdwsRestAuthenticationInfo, error) {
        if (authResponse.StatusCode != http.StatusOK) {
                return nil, fmt.Errorf(fmt.Sprintf("Authentication failed with statusCode: %d", authResponse.StatusCode))
        }
	responseBody, err := ioutil.ReadAll(authResponse.Body)
	if (err != nil) {
		return nil, err
	}
	var jsonResponse OioIdwsRestAuthResponse
        err = json.Unmarshal([]byte(responseBody), &jsonResponse)
	if (err != nil) {
                log.Println(fmt.Sprintf("[ERROR] error unmarshalling response: %s", responseBody))
		return nil, err
	}
        return &OioIdwsRestAuthenticationInfo{ Token: fmt.Sprintf("%s %s", jsonResponse.TokenType, jsonResponse.AccessToken), ExpiresIn: jsonResponse.ExpiresIn }, nil
}
