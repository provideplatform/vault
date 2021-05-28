package common

import (
	"os"

	"github.com/joho/godotenv"
	logger "github.com/kthomas/go-logger"
	"github.com/kthomas/go-redisutil"
)

// UnsealerKeyRequiredBytes is the required length of the UnsealerKey in bytes
const UnsealerKeyRequiredBytes = 32

var (
	// Log is the configured logger
	Log *logger.Logger
)

func init() {
	godotenv.Load()
	redisutil.RequireRedis()
	requireLogger()
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
