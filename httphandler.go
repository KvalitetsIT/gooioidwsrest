package oioidwsrest

import (
        "net/http"
)

type httpHandler func(http.ResponseWriter, *http.Request) (int, error)
