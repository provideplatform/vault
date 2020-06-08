module github.com/provideapp/vault

go 1.13

require (
	github.com/ethereum/go-ethereum v1.9.12
	github.com/gin-gonic/gin v1.6.3
	github.com/golang-migrate/migrate v3.5.4+incompatible
	github.com/jinzhu/gorm v1.9.12
	github.com/joho/godotenv v1.3.0
	github.com/kthomas/go-db-config v0.0.0-20190930131840-6f8768ecee4c
	github.com/kthomas/go-logger v0.0.0-20200602072946-d7d72dfc2531
	github.com/kthomas/go-pgputil v0.0.0-20200602073402-784e96083943
	github.com/kthomas/go-self-signed-cert v0.0.0-20200602041729-f9878375d46e
	github.com/kthomas/go.uuid v1.2.1-0.20190324131420-28d1fa77e9a4
	github.com/onsi/ginkgo v1.12.3
	github.com/onsi/gomega v1.10.1
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/provideapp/ident v0.0.0-20200524081406-b769dde4917c
	github.com/provideservices/provide-go v0.0.0-20200602074127-6898dccd0ba1
	golang.org/x/crypto v0.0.0-20200604202706-70a84ac30bf9
)

replace github.com/provideapp/ident => ../ident
