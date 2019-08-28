package kitcaddy

import (
	"github.com/beevik/etree"
)

const id_attr			= "ID"
const namespace_ds		= "xmlns:ds"
const namespace_wsu		= "xmlns:wsu"
const namespace_wst		= "xmlns:wst"
const namespace_wsse		= "xmlns:wsse"
const uri_ds			= "http://www.w3.org/2000/09/xmldsig#"
const uri_wsu 			= "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
const uri_wst			= "http://docs.oasis-open.org/ws-sx/ws-trust/200512"
const uri_wsse			= "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"

func CreateIssueRequest(keyInfoElement *etree.Element) (*etree.Document, *etree.Element, *etree.Element, []*etree.Element) {


	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)

	envelope := doc.CreateElement("soap:Envelope")
	envelope.CreateAttr("xmlns:soap", "http://schemas.xmlsoap.org/soap/envelope")

		header := envelope.CreateElement("soap:Header")

			action := header.CreateElement("Action")
			actionId := "_2451b4b1-38d6-4395-9a28-372560725c59" //TODO
			action.CreateAttr("xmlns", "http://www.w3.org/2005/08/addressing")
			action.CreateAttr(namespace_wsu, uri_wsu)
			action.CreateAttr(id_attr, actionId)
			action.SetText("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue")

			security := header.CreateElement("wsse:Security")
			security.CreateAttr(namespace_wsse, uri_wsse)
			security.CreateAttr(namespace_wsu, uri_wsu)
			security.CreateAttr("soap:mustUnderstand", "1")

		body := envelope.CreateElement("soap:Body")
		body.CreateAttr(namespace_wsu, uri_wsu)
		bodyActionId := "_a7dd77e4-586d-47b5-9b83-2ed20ff0441" // TODO
		body.CreateAttr(id_attr, bodyActionId)

			requestSecurityToken := body.CreateElement("wst:RequestSecurityToken")
			requestSecurityToken.CreateAttr(namespace_wst, uri_wst)
			requestSecurityToken.CreateAttr(namespace_ds, uri_ds)

				useKey := requestSecurityToken.CreateElement("wst:UseKey")

				useKey.AddChild(keyInfoElement)

	return doc, security, body, []*etree.Element{ action }
}

