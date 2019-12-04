# gooioidwdrest

# Opstart af udviklingsmiljø                              

Der ligger et docker-compose setup, som sætter udviklingsmiljøet op i 'testgooioidwsrest'.
Start først databaserne og dernæst sikkerhedskomponenter. De ligger i to forskellige docker-compose filer. Alle containere vil starte i et Docker network kaldet 'gooioidwsrest'.

```
docker-compose -f docker-compose-db.yml up

docker-compose up
```

Når udviklingsmiljøet er startet kan du gå i gang med at lave ændringer og bygge lokalt (se nedenfor).


# Hvis du vil bygge lokalt

Inden du kan bygge lokalt skal du have lavet et image med en ssh nøgle til GitHub som skal bruges under byg.
Dette image skal bare ligge lokalt på din maskine, så det giver ikke problemer i forhold til sikkerheden.

Sådan gør du:

- Du skal sørge for at du kan autentificere dig hos GitHub med SSH nøgle: [Connecting to GitHub with SSH](https://help.github.com/en/articles/connecting-to-github-with-ssh)
- Læs din SSH nøgle ind i en ENV variable og byg dit kit/git sådan her: 
```
SSH_PRIVATE_KEY=`cat ~/.ssh/id_rsa_github`
docker build -t kit/git -f Dockerfile-github . --build-arg SSH_PRIVATE_KEY="${SSH_PRIVATE_KEY}"
```

Derefter kan du bygge fra rodfolderen med kommandoen:
```
docker build --network testgooioidwsrest_gooioidwsrest  -t kvalitetsit/gooioidwsrest .
```

Bemærk at build forgår i samme netværk som udviklingsmiljøet, da testene anvender udviklingsmiljøets services.

# kvalitetsit/caddy-gooioidwsrest

OIO IDWS REST protokollen bliver leveret som en række plugins til [https://caddyserver.com/](https://caddyserver.com/).

Mongodb anvendes som session cache. 

## Miljøvariable og konfiguration

kvalitetsit/caddy-gooioidwsrest kan konfigureres med følgende ENV variable:

Varibelnavn  | Beskrivelse                                    | Obligatorisk | Defaultværdi    |
------------ | ---------------------------------------------- | ------------ | --------------- |
mongo_host   | Hostnavn for mongo server                      | Ja           | Ingen           |
mongo_port   | Portnummer for mongo service                   | Nej          | 27017           |

Derudover sker konfigurationen vha en konfigurationsfil - se f.eks [Caddyfile Primer](https://caddyserver.com/tutorial/caddyfile).

Sikkerhedsprotokollen konfigurers vha direktiverne:
* oioidwsrestwsc

### Dokumentation af oioidwsrestwsc

#### Konfiguration
Konfigurationen består af følgende felter:

```
        oioidwsrestwsc {
                mongo_db		value

                sts_url			value

                client_cert_file	value
                client_key_file		value

                trust_cert_files	certs...

                service_endpoint	value
                service_audience        value

		session_data_url	value
        }
```

* **mongo_db** er en obligatorisk opsætning med navnet på databaseinstancen i mongo
* **sts_url** er en obligarisk opsætning med endpoint for STS issue service
* **client_cert_file** er en obligatorisk opsætning med sti til clientcertifikatet til anvendelse i kommunikation med STS (CER)
* **client_key_file** er en obligatorisk opsætning med sti til clientnøgle til anvendelse i kommunikation med STS (PEM)
* **trust_cert_files** en optionel list af stier til SSL certifikater, der skal trustes i forbindelse med autentificering (f.eks. for STS og provider)
* **service_endpoint** er en obligatorisk opsætning URL til service endpoint
* **service_audience** er en obligatorisk opsætning til det audience SAML tokenet skal udstedes til
* **session_data_url** er en optionel opsætning, hvis WSC står bag en WSP, hvor token- og sessionoplysninger kan afhentes på URL

#### Anvendelse
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
