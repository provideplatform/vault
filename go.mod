module github.com/provideapp/vault

go 1.16

replace github.com/provideapp/ident => ../ident

require (
	github.com/Azure/azure-sdk-for-go v54.3.0+incompatible
	github.com/ethereum/go-ethereum v1.10.3
	github.com/gin-gonic/gin v1.7.2
	github.com/golang-migrate/migrate v3.5.4+incompatible
	github.com/jinzhu/gorm v1.9.16
	github.com/joho/godotenv v1.3.0
	github.com/kthomas/go-azure-wrapper v0.0.0-20210409115636-8b71edfc2fcc
	github.com/kthomas/go-db-config v0.0.0-20200612131637-ec0436a9685e
	github.com/kthomas/go-logger v0.0.0-20210526080020-a63672d0724c
	github.com/kthomas/go-pgputil v0.0.0-20200602073402-784e96083943
	github.com/kthomas/go.uuid v1.2.1-0.20190324131420-28d1fa77e9a4
	github.com/miguelmota/go-ethereum-hdwallet v0.0.1
	github.com/onsi/ginkgo v1.16.2
	github.com/onsi/gomega v1.12.0
	github.com/provideapp/ident v0.0.0-00010101000000-000000000000
	github.com/provideservices/provide-go v0.0.0-20210526080135-56bf9dc77084
	github.com/tyler-smith/go-bip32 v1.0.0
	github.com/tyler-smith/go-bip39 v1.1.0
	golang.org/x/crypto v0.0.0-20210513164829-c07d793c2f9a
)
