package kitcaddy

import (
	"testing"
	"crypto/tls"
//	"encoding/pem"
//        "github.com/russellhaering/gosaml2/types"

 	"gotest.tools/assert"
//  	"github.com/russellhaering/goxmldsig"
//	"io/ioutil"
)

func TestGetToken(t *testing.T) {

	// Given
	clientKeyPair, err := tls.LoadX509KeyPair("./testdata/medcom.cer", "./testdata/medcom.pem")
	assert.NilError(t, err)
	subject := NewStsClient(&clientKeyPair)


	// When
	subject.GetToken()



	// Given
//	clientCert, err := ioutil.ReadFile("./testdata/client.crt")
//	block, _ := pem.Decode([]byte(clientCert))
//	cert, err := x509.ParseCertificate(block.Bytes)
//	context := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
 //       	Roots: []*x509.Certificate { cert },
 //   	})

   /*     subject := NewTokenAuthenticator(context)
	bs, err := ioutil.ReadFile("./testdata/authenticate_body_first")
	assert.NilError(t, err, "couldn't read testdata authenticate_body_first")

	// When
	assertion, errProcess := subject.ParseAndValidateAuthenticationRequestPayload(bs) 

	// Then
	assert.NilError(t, errProcess)
	assert.Equal(t, assertion.Version, "2.0")
	assert.Equal(t, len(assertion.AttributeStatement.Attributes), 4)
	// TODO: tjek flere*/
}




// Testcase med forkert udsteder

// Testcase

