FROM kit/git as sshsecret

#1.12.7
FROM golang:1.13.4 as builder
ENV GO111MODULE=on

# add credentials on build and make sure github.xom is accepted
RUN mkdir /root/.ssh/
COPY --from=sshsecret /id_rsa /root/.ssh/id_rsa
RUN chmod 700 /root/.ssh/id_rsa
RUN touch /root/.ssh/known_hosts
RUN ssh-keyscan github.com >> /root/.ssh/known_hosts
ADD gitconfig /root/.gitconfig

# Prepare for custom caddy build
RUN mkdir /oioidwsrest
WORKDIR /oioidwsrest
RUN go mod init oioidwsrest

RUN echo "replace github.com/russellhaering/goxmldsig => github.com/evtr/goxmldsig latest" >> go.mod


ENV GOPRIVATE="github.com/KvalitetsIT/gosecurityprotocol,github.com/KvalitetsIT/gostsclient"
# Using Docker's layers to cache the following libraries
#RUN go get github.com/caddyserver/caddy
RUN echo "kuk11 d224"
RUN go get github.com/google/uuid
RUN go get github.com/KvalitetsIT/gosecurityprotocol
RUN go get github.com/KvalitetsIT/gostsclient
RUN go get github.com/russellhaering/gosaml2
RUN go get gotest.tools/assert

# Kitcaddy module source
COPY . /oioidwsrest/
RUN go test oioidwsrest
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /go/bin/oioidwsrest .
