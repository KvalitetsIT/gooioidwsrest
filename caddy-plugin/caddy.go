package main

import (
        "github.com/caddyserver/caddy/caddy/caddymain"
        _ "github.com/miekg/caddy-prometheus"
        _ "caddy/caddyoioidwsrest"
)

func main() {
        // optional: disable telemetry
        // caddymain.EnableTelemetry = false
        caddymain.Run()
}

