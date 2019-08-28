FROM golang:1.12.7 as builder
ENV GO111MODULE=on

# Prepare for custom caddy build
RUN mkdir /oioidwsrest
WORKDIR /oioidwsrest
RUN go mod init oioidwsrest

# Kitcaddy module source
COPY . /oioidwsrest/
RUN go test oioidwsrest
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /go/bin/caddy .
