module github.com/jiuzhang-waf/gateway

go 1.25.6

require (
	github.com/cilium/ebpf v0.22.0
	github.com/corazawaf/coraza/v3 v3.7.0
	github.com/google/gopacket v1.1.19
	github.com/jiuzhang-waf/gateway/dynamic_security v0.0.0
	github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard v0.0.0
	github.com/jiuzhang-waf/gateway/pcapevidence v0.0.0
	golang.org/x/sys v0.47.0
)

require (
	github.com/andybalholm/brotli v1.3.0 // indirect
	github.com/corazawaf/libinjection-go v0.3.2 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/goccy/go-yaml v1.18.0 // indirect
	github.com/gotnospirit/makeplural v0.0.0-20180622080156-a5f48d94d976 // indirect
	github.com/gotnospirit/messageformat v0.0.0-20221001023931-dfe49f1eb092 // indirect
	github.com/kaptinlin/go-i18n v0.1.4 // indirect
	github.com/kaptinlin/jsonschema v0.4.6 // indirect
	github.com/magefile/mage v1.17.2 // indirect
	github.com/petar-dambovaliev/aho-corasick v0.0.0-20250424160509-463d218d4745 // indirect
	github.com/tidwall/gjson v1.18.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/valllabh/ocsf-schema-golang v1.0.3 // indirect
	github.com/vektah/gqlparser/v2 v2.5.60 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	rsc.io/binaryregexp v0.2.0 // indirect
)

replace github.com/jiuzhang-waf/gateway/dynamic_security => ./dynamic_security

replace github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard => ./modules/jiuzhang_guard

replace github.com/jiuzhang-waf/gateway/pcapevidence => ./pcapevidence
