package oioidwsrest

import (
	"testing"
 	"gotest.tools/assert"
	"io/ioutil"
)

func TestParseAuthenticationRequestPayload(t *testing.T) {

	// Given
        subject := NewTokenAuthenticator("", []string { "./testdata/test_ca.crt" }, false)
	bs, err := ioutil.ReadFile("./testdata/authenticate_body_first")
	assert.NilError(t, err, "couldn't read testdata authenticate_body_first")

	// When
	authAssertion, errProcess := subject.ParseAndValidateAuthenticationRequestPayload(string(bs), nil) 

	// Then
	assert.NilError(t, errProcess)
	assert.Equal(t, authAssertion.assertion.Version, "2.0")
	assert.Equal(t, len(authAssertion.assertion.AttributeStatement.Attributes), 4)
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
        _, errProcess := subject.ParseAndValidateAuthenticationRequestPayload(string(bs), nil) 

        // Then
	assert.Error(t, errProcess, "Could not verify certificate against trusted certs")
}


// Testcase udløbet