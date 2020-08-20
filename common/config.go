package common

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
	logger "github.com/kthomas/go-logger"
	selfsignedcert "github.com/kthomas/go-self-signed-cert"
	"github.com/provideapp/ident/common"
)

var (
	// Log is the configured logger
	Log *logger.Logger

	// ListenAddr is the http server listen address
	ListenAddr string

	// CertificatePath is the SSL certificate path used by HTTPS listener
	CertificatePath string

	// PrivateKeyPath is the private key used by HTTPS listener
	PrivateKeyPath string

	// ServeTLS is true when CertificatePath and PrivateKeyPath are valid
	ServeTLS bool

	// UnsealerKey is the encryption/decryption key for the vault keys
	// which are used to decrypt the private keys/seeds
	UnsealerKey *[]byte

	// CloakingKey will ensure Infinity Key is encrypted in memory until required
	CloakingKey *[]byte

	// UskValidationHash is the validation hash for the Unsealer Key
	UskValidationHash *string

	// TempCounter for debugging
	TempCounter int
)

func init() {
	if err := godotenv.Load(); err != nil {
		common.Log.Debug(".env file not found")
	}
	common.Log.Debugf("here - gotdotenv loaded %s", os.Getenv("USK_VALIDATION_HASH"))
	requireLogger()
	requireGin()
	requireSealerValidationHash()
}

func requireGin() {
	ListenAddr = os.Getenv("LISTEN_ADDR")
	if ListenAddr == "" {
		listenPort := os.Getenv("PORT")
		if listenPort == "" {
			listenPort = "8080"
		}
		ListenAddr = fmt.Sprintf("0.0.0.0:%s", listenPort)
	}

	requireTLSConfiguration()
}

func requireLogger() {
	lvl := os.Getenv("LOG_LEVEL")
	if lvl == "" {
		lvl = "INFO"
	}

	var endpoint *string
	if os.Getenv("SYSLOG_ENDPOINT") != "" {
		endpt := os.Getenv("SYSLOG_ENDPOINT")
		endpoint = &endpt
	}

	Log = logger.NewLogger("vault", lvl, endpoint)
}

func requireSealerValidationHash() {
	if UskValidationHash != nil {
		common.Log.Debugf("validation hash somehow already set value: %s, address %p", *UskValidationHash, UskValidationHash)
	}

	if UskValidationHash == nil {
		//ensure the vault unsealer key is nil by default and we have the validation hash
		//UnsealerKey = nil
		hash := os.Getenv("USK_VALIDATION_HASH")

		UskValidationHash = &hash

		common.Log.Debugf("here - setting validation hash to %s, address %p", *UskValidationHash, UskValidationHash)

		TempCounter++ //how many times is this being set?

		common.Log.Debugf("here - validation hash set to %s, address %p", *UskValidationHash, UskValidationHash)
	}
}

func requireTLSConfiguration() {
	certificatePath := os.Getenv("TLS_CERTIFICATE_PATH")
	privateKeyPath := os.Getenv("TLS_PRIVATE_KEY_PATH")
	if certificatePath != "" && privateKeyPath != "" {
		CertificatePath = certificatePath
		PrivateKeyPath = privateKeyPath
		ServeTLS = true
	} else if os.Getenv("REQUIRE_TLS") == "true" {
		privKeyPath, certPath, err := selfsignedcert.GenerateToDisk([]string{})
		if err != nil {
			Log.Panicf("failed to generate self-signed certificate; %s", err.Error())
		}
		PrivateKeyPath = *privKeyPath
		CertificatePath = *certPath
		ServeTLS = true
	}
}
