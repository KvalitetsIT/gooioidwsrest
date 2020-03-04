#1.12.7
FROM golang:1.13.4 as builder
ENV GO111MODULE=on

# Prepare for custom caddy build
RUN mkdir /oioidwsrest
WORKDIR /oioidwsrest
COPY go.mod go.mod
# Download dependencies
RUN go mod download

# Kitcaddy module source
COPY . /oioidwsrest/
RUN go test oioidwsrest
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /go/bin/oioidwsrest .
