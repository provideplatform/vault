package common

import (
	"os"
	"strings"

	"github.com/joho/godotenv"
	logger "github.com/kthomas/go-logger"
	"github.com/provideapp/ident/common"
)

// UnsealerKeyRequiredBytes is the required length of the UnsealerKey in bytes
const UnsealerKeyRequiredBytes = 32

var (
	// Log is the configured logger
	Log *logger.Logger

	// UnsealerKeyValidationHash is the SHA256 validation hash for the unsealer key
	UnsealerKeyValidationHash string
)

func init() {
	godotenv.Load()

	requireLogger()
	requireSealerValidationHash()
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
	if os.Getenv("SEAL_UNSEAL_VALIDATION_HASH") == "" {
		common.Log.Warning("vault unsealer key validation hash not provided")
	} else {
		UnsealerKeyValidationHash = strings.Replace(os.Getenv("SEAL_UNSEAL_VALIDATION_HASH"), "0x", "", -1)
		common.Log.Debugf("vault validation hash set %s", UnsealerKeyValidationHash)
	}
}
