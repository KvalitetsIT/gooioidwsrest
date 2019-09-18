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
