module github.com/teslashibe/scarlett-node

go 1.25.13

require (
	filippo.io/edwards25519 v1.1.0
	github.com/ncruces/go-sqlite3 v0.34.4
	github.com/teslashibe/open-agent-api v0.1.31
	github.com/teslashibe/x-go v1.13.0
	golang.org/x/sys v0.45.0
	golang.org/x/term v0.34.0
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/joho/godotenv v1.5.1 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/ncruces/go-sqlite3-wasm/v2 v2.6.35302 // indirect
	github.com/ncruces/julianday v1.0.0 // indirect
	github.com/prometheus/client_golang v1.23.2 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.66.1 // indirect
	github.com/prometheus/procfs v0.17.0 // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	google.golang.org/protobuf v1.36.8 // indirect
)

// Private runtime snapshot; source hashes are in third_party/x-go/UPSTREAM.json.
replace github.com/teslashibe/x-go v1.13.0 => ./third_party/x-go
