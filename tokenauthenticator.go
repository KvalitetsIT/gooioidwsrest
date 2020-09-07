package oioidwsrest

import (
	"net/http"
	"io/ioutil"
	"bytes"
	"io"
	"strings"
	"encoding/xml"
	"encoding/base64"

	"math/big"

	"regexp"

	"fmt"

	"crypto/rsa"
        "crypto/x509"
	"crypto/sha256"
        "encoding/pem"

	"github.com/russellhaering/gosaml2/types"
	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"
	dsigtypes "github.com/russellhaering/goxmldsig/types"
	"github.com/beevik/etree"

	"go.uber.org/zap"
)

var whiteSpace = regexp.MustCompile("\\s+")

type AuthenticatedAssertion struct {
	assertion *types.Assertion
	subjectConfimationMethod string
}

type TokenAuthenticator struct {
	validationContext *dsig.ValidationContext
	samlServiceProvider *saml2.SAMLServiceProvider
	validateSamlConstraints bool

	logger *zap.SugaredLogger
}

func (a AuthenticatedAssertion) GetAssertion() (*types.Assertion)  {

	return a.assertion
}

func NewTokenAuthenticator(audienceRestriction string, certPaths []string, validateSamlConstraints bool, logger *zap.SugaredLogger) *TokenAuthenticator {

	var certs []*x509.Certificate
	for _, certPath := range certPaths {
		caCert, err := ioutil.ReadFile(certPath)
        	block, _ := pem.Decode([]byte(caCert))
        	cert, err := x509.ParseCertificate(block.Bytes)
		if (err != nil) {
			panic(err)
		}
		certs = append(certs, cert)
	}
	context := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
                Roots: certs,
        })


	t := new(TokenAuthenticator)
	t.validationContext = context
	sp := new(saml2.SAMLServiceProvider)
	sp.AudienceURI = audienceRestriction
	t.samlServiceProvider = sp
	t.validateSamlConstraints = validateSamlConstraints
	t.logger = logger

	return t;
}

func (t TokenAuthenticator) Authenticate(clientCert *x509.Certificate, r *http.Request) (string, *AuthenticatedAssertion, error) {
	path := r.URL.Path
	if (strings.HasSuffix(path, "/authenticate") || strings.HasSuffix(path, "/token")) {
		body, err := ioutil.ReadAll(r.Body)
		t.logger.Debug("WSP received authentication request")
		if (err != nil) {
			return "", nil, err
		}
		return t.processAuthenticationRequest(clientCert, body)
	}

	return "", nil, nil
}


func (t TokenAuthenticator) processAuthenticationRequest(clientCert *x509.Certificate, body []byte) (string, *AuthenticatedAssertion, error) {

	// Retrive the assertion from the body
	assertionStr := strings.TrimPrefix(string(body), "saml-token=")

	// Parse the assertion
	decodedAssertion, authenticatedAssertion, err := t.ParseAndValidateAuthenticationRequestPayload(assertionStr, clientCert)
	if (err != nil) {
		t.logger.Info(fmt.Sprintf("Received body from authentication request did not contain legal assertion (err: %s)", err.Error()))
		return assertionStr, nil, err
	}

	return decodedAssertion, authenticatedAssertion, err
}

func (t TokenAuthenticator) ParseAndValidateAuthenticationRequestPayload(body string, clientCert *x509.Certificate) (string, *AuthenticatedAssertion, error) {

	auth := AuthenticatedAssertion{}

	clientCertIdentification := "<no client cert>"
	if (clientCert != nil) {
		// Extract cert info for logging purposes
		clientCertIdentification = clientCert.Subject.CommonName
	}
	// Check that there is some input for validation
	if (len(body) == 0) {
		t.logger.Debug(fmt.Sprintf("Error authenticating: Input in body was empty"))
		return "", nil, fmt.Errorf("Error authenticating: Input in body was empty")
	}

    // Base64 decode
    decoded, err := base64.StdEncoding.DecodeString(body)
	if (err != nil) {
		t.logger.Debug(fmt.Sprintf("Error decoding authentication request body (request body: %s) (client certificate subject commonname: %s) (error: %s)", body, clientCertIdentification, err.Error()))
		return "", nil, err
	}

	// Validate signature of the issuer of the Assertion
	doc := etree.NewDocument()
	err = doc.ReadFromBytes(decoded)
	if (err != nil) {
		t.logger.Debug(fmt.Sprintf("Error parsing XML from authentication request (decoded payload: %s) (client certificate subject commonname: %s) (error: %s)", decoded, clientCertIdentification, err.Error()))
		return "", nil, err
	}
	_, err = t.validationContext.Validate(doc.Root())
    	if (err != nil) {
		t.logger.Debug(fmt.Sprintf("Error validating authentication request (decoded payload: %s) (client certificate subject commonname: %s) (error: %s)", decoded, clientCertIdentification, err.Error()))
		return "", nil, err
    	}

        // Parse the assertion
        assertion := &types.Assertion{}
        xmlDecoder := xml.NewDecoder(bytes.NewReader(decoded))
        xmlDecoder.CharsetReader = identReader
        err = xmlDecoder.Decode(&assertion)
	if (err != nil) {
		return "", nil, err
	}

	// TODO: Check assertion is valid according to SAML specification
	if (t.validateSamlConstraints) {

		warningInfo, err := t.samlServiceProvider.VerifyAssertionConditions(assertion)
		if (err != nil) {
			t.logger.Debug(fmt.Sprintf("Error verifying conditions authentication request (decoded payload: %s) (client certificate subject commonname: %s) (error: %s)", decoded, clientCertIdentification, err.Error()))
			return "", nil, err
		}
		if (warningInfo != nil && warningInfo.InvalidTime) {
			t.logger.Debug(fmt.Sprintf("Error verifying time constraints authentication request (decoded payload: %s) (client certificate subject commonname: %s)", decoded, clientCertIdentification))
			return "", nil, fmt.Errorf("SAML Assertion was not valid due to invalid time")
		}

		if ((len(t.samlServiceProvider.AudienceURI) > 0) && warningInfo != nil && warningInfo.NotInAudience) {
			t.logger.Debug(fmt.Sprintf("Error verifying audience authentication request (decoded payload: %s) (client certificate subject commonname: %s)", decoded, clientCertIdentification))
			return "", nil, fmt.Errorf("SAML Assertion was not valid due to audience restriction")
		}
	}

	// Compare KeyInfo from subject (HoK)
	if (clientCert != nil) {

		// Calculate hash of public key in client cert to compare with public key in assertion
                clientCertPubBytes, err := x509.MarshalPKIXPublicKey(clientCert.PublicKey)
                if (err != nil) {
                	return "", nil, fmt.Errorf(fmt.Sprintf("Could not marshal public key from client SSL"))
                }
                clientCertHash := sha256.Sum256(clientCertPubBytes)


		// Find subjectkeyinfo in assertion and parse it into structure
		subjectKeyInfoPath, err := etree.CompilePath("./Assertion/Subject/SubjectConfirmation/SubjectConfirmationData/KeyInfo")
		if (err != nil) {
			return "", nil, fmt.Errorf("Could not compile xpath for subjectkeyinfo")
		}
		keyInfoElement := doc.FindElementPath(subjectKeyInfoPath)
		if (keyInfoElement == nil) {
			return "", nil, fmt.Errorf("Could not find KeyInfo element in SubjectConfirmationData in assertion")
		}

		keyInfoDoc := etree.NewDocument()
		keyInfoDoc.SetRoot(keyInfoElement)
		keyInfoDocStr, err := keyInfoDoc.WriteToString()
		if (err != nil) {
			return "", nil, fmt.Errorf("Error serializing Key Info document")
		}
		keyInfo := &dsigtypes.KeyInfo{}
		keyInfoDecoder := xml.NewDecoder(bytes.NewReader([]byte(keyInfoDocStr)))
                keyInfoDecoder.CharsetReader = identReader
                err = keyInfoDecoder.Decode(&keyInfo)
		if (err != nil) {
			return "", nil, fmt.Errorf("Could not decode keyInfo document")
		}

		// Find public key in assertion
		if (len(keyInfo.X509Data.X509Certificates) > 0) {
			// Its right there
			return "", nil, fmt.Errorf("Not implemented 48325932 -should be easy though")
                } else {
			// Its not embedded - construct public key in assertion from modulus and exponent
			modulusPath, err := etree.CompilePath("./KeyInfo/KeyValue/RSAKeyValue/Modulus")
			if (err != nil) {
       	                        return "", nil, fmt.Errorf("Could not compile xpath for modulus")
       	       	        }
			exponentPath, err := etree.CompilePath("./KeyInfo/KeyValue/RSAKeyValue/Exponent")
			if (err != nil) {
                       	        return "", nil, fmt.Errorf("Could not compile xpath for exponent")
                       	}

			modulusElement := keyInfoDoc.FindElementPath(modulusPath)
			exponentElement := keyInfoDoc.FindElementPath(exponentPath)
			if (modulusElement == nil || exponentElement == nil) {
				return "", nil, fmt.Errorf("Modulus or Exponent not found")
			}

			modFromAssertion := modulusElement.Text()
			decodedModFromAssertion, err := base64.StdEncoding.DecodeString(modFromAssertion)
			if (err != nil) {
				return "", nil, fmt.Errorf(fmt.Sprintf("Could not decode modulus from assertion (value from assertion: %s)", modFromAssertion))
			}

			e := 65537 // Most likely :-)
			publicKeyFromAssertion := &rsa.PublicKey{N: new(big.Int).SetBytes(decodedModFromAssertion), E: e}
			derPublicKeyFromAssertion, err := x509.MarshalPKIXPublicKey(publicKeyFromAssertion)
			if (err != nil) {
				return "", nil, fmt.Errorf(fmt.Sprintf("Could not marshal public key from assertion"))
			}
			assertionHash := sha256.Sum256(derPublicKeyFromAssertion)

			// Compare hashes to ensure HoK
			if (assertionHash != clientCertHash) {
				return "", nil, fmt.Errorf(fmt.Sprintf("Public key in assertion does not match client SSL certificate"))
			}
		}
	}
	auth.assertion = assertion

	return string(decoded), &auth, err
}

func identReader(encoding string, input io.Reader) (io.Reader, error) {
    return input, nil
}

