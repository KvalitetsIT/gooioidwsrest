# OIO IDWS REST
Er et Docker image, der indeholder implementationer af hhv
* Web Service Consumer (WSC)
* Web Service Producer (WSP)
For sikkerhedsprotokollen OIO IDWS REST

Både WSC og WSP er lavet som moduler til open source web serveren [Caddy](https://caddyserver.com/).
Til caching af hhv. tokens og sessions anvendes MongoDb.

## Konfiguration
konfigureres som dokumenteret i vejledningerne til Caddy dvs. med en konfigurationsfil [V2: Config from Scratch](https://github.com/caddyserver/caddy/wiki/v2:-Config-from-Scratch)

For at gøre konfigurationen lettere kan du anvende imaget TODO til at generere en passende konfigurationsfil.

Varibelnavn  | Beskrivelse | Eksempel |
------------ | ----------- | -------- |
TEMPLATE_FILE | Den template, der ønskes benyttet til genereringen | /caddyfiletemplates/Caddyfile-wsc-nosessiondata |
CADDYFILE | Outputfil for den genererede Caddyfile | /output/Caddyfile-test |

For WSC findes to forskellige templates:
* /caddyfiletemplates/Caddyfile-wsc: En WSC der er placeret bagved en WSP (hvor den skal hente session data i forbindelse med trækning/veksling af SAML tokens)
* /caddyfiletemplates/Caddyfile-wsc-nosessiondata: En "standalone" WSC (dvs uden WSC_SESSION_DATA_URL)

Til genereringen af konfigurationfil for WSC skal følgende ENV variable sættes:

Varibelnavn                 | Beskrivelse                                    | Eksempel                             |
--------------------------- | ---------------------------------------------- | ------------------------------------ |
LISTEN                      | Den HTTP port, som containeren skal lytte på   | 8080                                 |
MONGO_HOST                  | Hostnavn for MongoDb | mongodb |
MONGO_DATABASE              | Databasenavn for MongoDb | wsc_tokens |
WSC_STS_URL                 | URL, der udpeger STS Issue endpoint            | https://www.myorg.dk/sts/service/sts |
WSC_SERVICE_AUDIENCE        | Audience, der bedes om i forhold til STS'ens udstedelse af SAML tokens | urn:kit:testa:servicea |
WSC_CLIENT_CERTIFICATE_FILE | Fil, der udpeger klientens certifikat | /config/client.cer |
WSC_CLIENT_KEY_FILE | Fil, der udpeger klientens private nøgle | /config/client.key |
WSC_TRUST_CERT_FILES | Liste af filer med certifikater, der skal trustes (typisk STS certifikat og evt. SSL certifikater | "/wsc/trust/sts.cer", "/wsc/trust/testssl.cer" |
WSC_SERVICE_ENDPOINT_HOST | Hostnavnet på den service, som WSC ønsker at gøre brug af | servicea.myorg.dk |
WSC_SERVICE_ENDPOINT_PORT | Porten, som servicen, som WSC ønsker at gøre brug af, lytter på | 443 |
WSC_SERVICE_ENDPOINT_CONTEXT | Context for servicen, som WSC ønsker at gøre brug af (kan være tom) | servicea |
WSC_SESSION_DATA_URL | Den url, hvor WSC kan hente sessionsdata (for setups, hvor WSC er placeret i forbindelse med en WSP) | https://testservicea |

For et eksempel (med docker-compose), der både anvender templategenerering og sætter WSC op med den genererede template, se: 
[docker-compose setup med generering af templates](./testgooioidwsrest/docker-compose-wsc.yml)

#### Anvendelse af WSC
Når oioidwsrestwsc er startet op kan den danne en proxy foran et sikret API, hvor sikkerhed håndteres.
Hvis man fra anvendersiden har brug for at påvirke token udstedelsen med extra claims kan disse sendes til oioidwsrestwsc i en optionel HTTP header:
```
	X-Claims værdi
```

Værdien af HTTP headeren forventes at være en base64 encoded streng f.eks:
```
WwoJeyAia2V5IjogInVybjp1c2Vycm9sZSIsICJ2YWx1ZSI6ICJhZG1pbiJ9LAoJeyAia2V5IjogInVybjplbWFpbCIsICJ2YWx1ZSI6ICJhZG1pbkBhZG1pbi5kayJ9Cl0=
```

Strukturen af værdien (decoded er som følger):
```
[
  { "key": "urn:userrole", "value": "admin"},
  { "key": "urn:email", "value": "admin@admin.dk"}
]

```

Således sendes en liste af key+value par, hvor *key* definerer navnet på claimen og *value* definerer værdien. 
