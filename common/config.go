/*
 * Copyright 2017-2024 Provide Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
