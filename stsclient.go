package kitcaddy

import (
	"fmt"
//	"bytes"
//	"io"
//	"encoding/xml"
//	"encoding/base64"
	"crypto/tls"
//	"crypto/x509"
	saml2 "github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
//	"github.com/russellhaering/goxmldsig/types"
	"github.com/beevik/etree"
)

type StsClient struct {
	keyStore		dsig.TLSCertKeyStore
	clientKeyPair		*tls.Certificate
	keyInfoElement		*etree.Element
}

func NewStsClient(keyPair *tls.Certificate) *StsClient{
	t := new(StsClient)
	t.clientKeyPair = keyPair
	t.keyStore = dsig.TLSCertKeyStore(*keyPair)
	keyInfoElement, err := getKeyInfoElement(t.keyStore)
	if (err != nil) {
		panic(err)
	}
	t.keyInfoElement = keyInfoElement
	return t
}

func (s StsClient) GetToken() (*saml2.Assertion, error) {


//	keyInfo := new(types.KeyInfo)
//	keyInfo.X509Data.X509Certificates = []*x509.Certificate { s.clientKeyPair.PrivateKey }

	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
	root := doc.CreateElement("Body")
	root.CreateAttr("ID", "root_abcd")

	people := root.CreateElement("People")
	people2 := root.CreateElement("People")
        people.CreateAttr("ID", "id1234")
	people2.CreateAttr("ID", "id1235")


//&dsig.MemoryX509KeyStore{
	//	privateKey: s.clientKeyPair.PrivateKey,
	//	cert:       s.clientKeyPair.Leaf,
//	}

	// Create the SOAP request
	document, security, body, headersToSign := CreateIssueRequest(s.keyInfoElement)

	document, _ = s.SignSoapRequest2(document, security, body, headersToSign)

        str, err := document.WriteToString()
        if err != nil {
                panic(err)
        }

        fmt.Println(str)

	return nil, nil
}

func (s StsClient) SignSoapRequest2(document *etree.Document, security *etree.Element, body *etree.Element, headersToSign []*etree.Element) (*etree.Document, error) {
        ctx := dsig.NewDefaultSigningContext(s.keyStore)
        contents, _ := ctx.Canonicalizer.Canonicalize(document.Root())

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(contents); err != nil {
	    	panic(err)
	}

	bodyPath, err := etree.CompilePath("/soap:Envelope/soap:Body")
	body = doc.FindElementPath(bodyPath)
	if (body == nil) {
                panic("body element not found")
        }


	securityPath, err := etree.CompilePath("/soap:Envelope/soap:Header/wsse:Security")
        security = doc.FindElementPath(securityPath)
        if (security == nil) {
                panic("security element not found")
        }


        // Start by signing the body and creating the Signature element under the Security node of the request
        signedBody, err := ctx.ConstructSignature(body, false)
        if (err != nil) {
                return nil, err
        }

        security.AddChild(signedBody)

        signedInfoPath, err := etree.CompilePath("/soap:Envelope/soap:Header/wsse:Security/ds:Signature/ds:SignedInfo")
        signedInfoElement := doc.FindElementPath(signedInfoPath)
        if (signedInfoElement == nil) {
                panic("element not found")
        }


	return doc, nil
        // Append each of the Request elements containing the header digests to the Signature element
/*        for _, header := range headersToSign {

                signedHeader, _ := ctx.ConstructSignature(header, false)
                doc := etree.NewDocument()
                doc.SetRoot(signedHeader)

                referencePath, _ := etree.CompilePath("./ds:Signature/ds:SignedInfo/ds:Reference")
                referenceElement := doc.FindElementPath(referencePath)
                if (referenceElement == nil) {
                        panic("element not found2")
                }

                signedInfoElement.AddChild(referenceElement)
        }*/

        // TODO: Create the signature based on all of the digests
        return doc, nil
}


func (s StsClient) SignSoapRequest(document *etree.Document, security *etree.Element, body *etree.Element, headersToSign []*etree.Element) error {
        ctx := dsig.NewDefaultSigningContext(s.keyStore)

        // Start by signing the body and creating the Signature element under the Security node of the request
        signedBody, err := ctx.ConstructSignature(body, false)
	if (err != nil) {
		return err
	}
        security.AddChild(signedBody)
        signedInfoPath, err := etree.CompilePath("/soap:Envelope/soap:Header/wsse:Security/ds:Signature/ds:SignedInfo")
        signedInfoElement := document.FindElementPath(signedInfoPath)
        if (signedInfoElement == nil) {
                panic("element not found")
        }

        // Append each of the Request elements containing the header digests to the Signature element
        for _, header := range headersToSign {

                signedHeader, _ := ctx.ConstructSignature(header, false)
                doc := etree.NewDocument()
                doc.SetRoot(signedHeader)

                referencePath, _ := etree.CompilePath("./ds:Signature/ds:SignedInfo/ds:Reference")
                referenceElement := doc.FindElementPath(referencePath)
                if (referenceElement == nil) {
                        panic("element not found2")
                }

                signedInfoElement.AddChild(referenceElement)
        }

        // TODO: Create the signature based on all of the digests
	return nil
}

func getKeyInfoElement(keyStore dsig.TLSCertKeyStore) (*etree.Element, error) {

	ctx := dsig.NewDefaultSigningContext(keyStore)

	doc := etree.NewDocument()
        doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
        root := doc.CreateElement("Root")
	root.CreateAttr("ID", "dummy")

	signed, err := ctx.SignEnveloped(root)
      	if (err != nil) {
		return nil, err
        }
	doc.SetRoot(signed)

	keyInfoPath, err := etree.CompilePath("./Root/ds:Signature/ds:KeyInfo")
	if (err != nil) {
                return nil, err
        }

	keyInfo := doc.FindElementPath(keyInfoPath)
	if (keyInfo == nil) {
		panic("keyinfo not found")
	}
	docResult := etree.NewDocument()
	docResult.SetRoot(keyInfo)

	return keyInfo, nil
}

/*func (s StsClient) createRequestSecurityTokenSoapEnvelope() {
	doc := etree.NewDocument()
        doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)

	// SOAP Envelope
	soapEnvelope := doc.CreateElement("Envelope")
}*/
