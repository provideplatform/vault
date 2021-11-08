package common

import (
	"os"

	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/joho/godotenv"
	logger "github.com/kthomas/go-logger"
)

// UnsealerKeyRequiredBytes is the required length of the UnsealerKey in bytes
const UnsealerKeyRequiredBytes = 32

var (
	// Log is the configured logger
	Log *logger.Logger

	// ConsumeNATSStreamingSubscriptions is a flag the indicates if the ident instance is running in API or consumer mode
	ConsumeNATSStreamingSubscriptions bool
)

func init() {
	godotenv.Load()
	requireLogger()
	requireBLS()
}

func requireBLS() {
	if err := bls.Init(bls.BLS12_381); err != nil {
		panic(err)
	}
	bls.SetETHmode(bls.EthModeDraft07)
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
