package oioidwsrest

import (
	"time"
        "net/http"
        "encoding/base64"
	"encoding/json"
        securityprotocol "github.com/KvalitetsIT/gosecurityprotocol"

)



type Claim struct {

        Key    string `json:"key"`
        Value  string `json:"value"`
}

func AddExtraClaimsToSessionData(sessionId string, sessionData *securityprotocol.SessionData, r *http.Request) (*securityprotocol.SessionData, error) {

        claimsHeaderValue := r.Header.Get(HTTP_HEADER_X_CLAIMS)
        if (len(claimsHeaderValue) == 0) {
                return sessionData, nil;
        }

        // Decode and unmarshal
        decodedClaimsHeaderValue, err := base64.StdEncoding.DecodeString(claimsHeaderValue)
        if (err != nil) {
                return nil, err
        }
        var claims []Claim
        err = json.Unmarshal(decodedClaimsHeaderValue, &claims)
        if (err != nil) {
                return nil, err
	}

        var resultData *securityprotocol.SessionData
        if (sessionData != nil) {
                resultData = sessionData
        } else {
                resultData, _ = securityprotocol.CreateSessionData("", make(map[string][]string), time.Now(), "")
        }

	for _, claim := range claims {
		resultData.AddSessionAttribute(claim.Key, claim.Value)
	}

        return resultData, nil
}

