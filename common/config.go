package common

import (
	"fmt"
	"os"
	"strings"

	"github.com/joho/godotenv"
	logger "github.com/kthomas/go-logger"
	selfsignedcert "github.com/kthomas/go-self-signed-cert"
	"github.com/provideapp/ident/common"
)

// UnsealerKeyRequiredBytes is the required length of the UnsealerKey in bytes
const UnsealerKeyRequiredBytes = 32

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

	// UnsealerKeyValidationHash is the SHA256 validation hash for the unsealer key
	UnsealerKeyValidationHash string
)

func init() {
	godotenv.Load()

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
	if os.Getenv("VAULT_USK_VALIDATION_HASH") == "" {
		common.Log.Warning("vault unsealer key validation hash not provided")
	} else {
		UnsealerKeyValidationHash = strings.Replace(os.Getenv("VAULT_USK_VALIDATION_HASH"), "0x", "", -1)
		common.Log.Debugf("vault validation hash set %s", UnsealerKeyValidationHash)
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
