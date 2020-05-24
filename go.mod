module github.com/provideapp/vault

go 1.13

require (
	github.com/ethereum/go-ethereum v1.9.7-0.20191017083913-a28093ced4e8
	github.com/gin-gonic/gin v1.6.3
	github.com/golang-migrate/migrate v3.5.4+incompatible
	github.com/jinzhu/gorm v1.9.12
	github.com/kthomas/go-db-config v0.0.0-20190930131840-6f8768ecee4c
	github.com/kthomas/go-logger v0.0.0-20190616094252-01c360658513
	github.com/kthomas/go-pgputil v0.0.0-20200117102704-9a684ec1c8a8
	github.com/kthomas/go-self-signed-cert v0.0.0-20200121102317-5ce1ee6149aa
	github.com/kthomas/go.uuid v1.2.1-0.20190324131420-28d1fa77e9a4
	github.com/onsi/ginkgo v1.12.0
	github.com/onsi/gomega v1.9.0
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/provideapp/ident v0.0.0-00010101000000-000000000000
	github.com/provideservices/provide-go v0.0.0-20200523141458-b060cca21864
	golang.org/x/crypto v0.0.0-20200510223506-06a226fb4e37
)

replace github.com/provideapp/ident => ../ident
