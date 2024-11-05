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

package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/kthomas/go-redisutil"

	"github.com/provideplatform/ident/common"
	"github.com/provideplatform/vault/api"

	util "github.com/provideplatform/provide-go/common/util"
)

const runloopSleepInterval = 250 * time.Millisecond
const runloopTickInterval = 5000 * time.Millisecond
const jwtVerifierRefreshInterval = 60 * time.Second
const jwtVerifierGracePeriod = 60 * time.Second

var (
	cancelF context.CancelFunc
	closing uint32
	ctx     context.Context
	sigs    chan os.Signal

	srv *http.Server
)

func init() {
	if common.ConsumeNATSStreamingSubscriptions {
		common.Log.Panicf("dedicated API instance started with CONSUME_NATS_STREAMING_SUBSCRIPTIONS=true")
		return
	}

	util.RequireJWTVerifiers()
	util.RequireGin()
	redisutil.RequireRedis()
	common.EnableAPIAccounting()
}

func main() {
	common.Log.Debugf("starting vault API...")
	installSignalHandlers()

	srv, _ = api.StartGin()

	startAt := time.Now()
	gracePeriodEndAt := startAt.Add(jwtVerifierGracePeriod)
	verifiersRefreshedAt := time.Now()

	timer := time.NewTicker(runloopTickInterval)
	defer timer.Stop()

	for !shuttingDown() {
		select {
		case <-timer.C:
			now := time.Now()
			if now.Before(gracePeriodEndAt) {
				util.RequireJWTVerifiers()
			} else if now.After(verifiersRefreshedAt.Add(jwtVerifierRefreshInterval)) {
				verifiersRefreshedAt = now
				util.RequireJWTVerifiers()
			}
		case sig := <-sigs:
			common.Log.Debugf("received signal: %s", sig)
			shutdown()
		default:
			time.Sleep(runloopSleepInterval)
		}
	}

	common.Log.Debug("exiting vault API")
	cancelF()
}

func installSignalHandlers() {
	common.Log.Debug("installing signal handlers for vault API")
	sigs = make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	ctx, cancelF = context.WithCancel(context.Background())
}

func shutdown() {
	if atomic.AddUint32(&closing, 1) == 1 {
		common.Log.Debug("shutting down vault API")

		signal.Stop(sigs)
		close(sigs)

		if srv != nil {
			srv.Shutdown(ctx)
		}
	}
}

func shuttingDown() bool {
	return (atomic.LoadUint32(&closing) > 0)
}
