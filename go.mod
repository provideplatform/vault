module github.com/provideapp/vault

go 1.13

require (
	github.com/FactomProject/basen v0.0.0-20150613233007-fe3947df716e // indirect
	github.com/FactomProject/btcutilecc v0.0.0-20130527213604-d3a63a5752ec // indirect
	github.com/cmars/basen v0.0.0-20150613233007-fe3947df716e // indirect
	github.com/ethereum/go-ethereum v1.9.22
	github.com/gin-gonic/gin v1.6.3
	github.com/golang-migrate/migrate v3.5.4+incompatible
	github.com/herumi/bls-eth-go-binary v0.0.0-20210102080045-a126987eca2b
	github.com/jinzhu/gorm v1.9.16
	github.com/joho/godotenv v1.3.0
	github.com/kthomas/go-db-config v0.0.0-20200612131637-ec0436a9685e
	github.com/kthomas/go-logger v0.0.0-20200602072946-d7d72dfc2531
	github.com/kthomas/go.uuid v1.2.1-0.20190324131420-28d1fa77e9a4
	github.com/miguelmota/go-ethereum-hdwallet v0.0.0-20200123000308-a60dcd172b4c
	github.com/onsi/ginkgo v1.14.0
	github.com/onsi/gomega v1.10.1
	github.com/provideapp/ident v0.0.0-00010101000000-000000000000
	github.com/provideservices/provide-go v0.0.0-20210203145430-f0f3f6d4035d
	github.com/tyler-smith/go-bip32 v1.0.0
	github.com/tyler-smith/go-bip39 v1.0.2
	golang.org/x/crypto v0.0.0-20200820211705-5c72a883971a
	launchpad.net/gocheck v0.0.0-20140225173054-000000000087 // indirect
)

replace github.com/provideapp/ident => ../ident
