module github.com/KvalitetsIT/gooioidwsrest

go 1.16

replace github.com/russellhaering/goxmldsig => github.com/evtr/goxmldsig v0.0.0-20190907195011-53d9398322c5

require (
	github.com/KvalitetsIT/gosecurityprotocol v1.0.1
	github.com/KvalitetsIT/gostsclient v1.0.1
	github.com/beevik/etree v1.1.0
	github.com/google/go-cmp v0.5.7
	github.com/google/uuid v1.3.0
	github.com/jonboulle/clockwork v0.2.3
	github.com/pkg/errors v0.9.1
	github.com/russellhaering/gosaml2 v0.6.0
	github.com/russellhaering/goxmldsig v1.1.0
	go.uber.org/atomic v1.9.0
	go.uber.org/multierr v1.7.0
	go.uber.org/tools v0.0.0-20190618225709-2cfd321de3ee // indirect
	go.uber.org/zap v1.19.1
	gotest.tools v2.2.0+incompatible
	honnef.co/go/tools v0.0.1-2019.2.3 // indirect
)
