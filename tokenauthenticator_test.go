package oioidwsrest

import (
	"testing"
 	"gotest.tools/assert"
	"io/ioutil"
	"encoding/base64"
)

func TestParseAuthenticationRequestPayload(t *testing.T) {

	// Given
        subject := NewTokenAuthenticator("", []string { "./testdata/test_ca.crt" }, false)
	bs, err := ioutil.ReadFile("./testdata/authenticate_body_first")
	assert.NilError(t, err, "couldn't read testdata authenticate_body_first")
	bsDecoded, errBsDecode := base64.StdEncoding.DecodeString(string(bs))
	assert.NilError(t, errBsDecode, "couldn't base64 decode testdata authenticate_body_first")

	// When
	decoded, authAssertion, errProcess := subject.ParseAndValidateAuthenticationRequestPayload(string(bs), nil) 

	// Then
	assert.NilError(t, errProcess)
	assert.Equal(t, authAssertion.assertion.Version, "2.0")
	assert.Equal(t, len(authAssertion.assertion.AttributeStatement.Attributes), 4)
	assert.Equal(t, decoded, string(bsDecoded), "Expected the decoded assertion to match that in the input data authenticate_body_first")
	// TODO: tjek flere
}

func TestParseAuthenticationRequestWithPrefix(t *testing.T) {

        // Given
        subject := NewTokenAuthenticator("", []string { "./testdata/test_ca.crt" }, false)
        bs, err := ioutil.ReadFile("./testdata/authenticate_body_first")
        assert.NilError(t, err, "couldn't read testdata authenticate_body_first")
	withPrefix := "saml-token="+string(bs)

        // When
        _, _, errProcess := subject.processAuthenticationRequest(nil, []byte(withPrefix)) 

        // Then
        assert.NilError(t, errProcess)
//	assert.Equal(t, "1224", sessionId)
}


func TestParseAuthenticationRequestPayloadWithTokenSignedByUnknownSts(t *testing.T) {

        // Given
        subject := NewTokenAuthenticator("", []string { "./testdata/test_ca.crt" }, false)
	bs, err := ioutil.ReadFile("./testdata/authenticate_local")
        assert.NilError(t, err, "couldn't read testdata authenticate_body_first")

        // When
        decoded, _, errProcess := subject.ParseAndValidateAuthenticationRequestPayload(string(bs), nil) 

        // Then
	assert.Error(t, errProcess, "Could not verify certificate against trusted certs")
	assert.Equal(t, decoded, "")
}


// Testcase udløbet
