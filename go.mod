module fdo-manufacturing-station

go 1.25.0

require (
	github.com/fido-device-onboard/go-fdo v0.0.0
	github.com/fido-device-onboard/go-fdo/fsim v0.0.0-20260116133239-94bd9c5d647c
	github.com/fido-device-onboard/go-fdo/sqlite v0.0.0
	github.com/nuts-foundation/go-did v0.17.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/lestrrat-go/blackmagic v1.0.2 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc v1.0.6 // indirect
	github.com/lestrrat-go/iter v1.0.2 // indirect
	github.com/lestrrat-go/jwx/v2 v2.1.4 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/multiformats/go-base32 v0.1.0 // indirect
	github.com/multiformats/go-base36 v0.2.0 // indirect
	github.com/multiformats/go-multibase v0.2.0 // indirect
	github.com/ncruces/go-sqlite3 v0.30.4 // indirect
	github.com/ncruces/julianday v1.0.0 // indirect
	github.com/segmentio/asm v1.2.0 // indirect
	github.com/shengdoushi/base58 v1.0.0 // indirect
	github.com/tetratelabs/wazero v1.11.0 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
)

replace github.com/fido-device-onboard/go-fdo => ./go-fdo

replace github.com/fido-device-onboard/go-fdo/sqlite => ./go-fdo/sqlite

replace github.com/fido-device-onboard/go-fdo/fsim => ./go-fdo/fsim
