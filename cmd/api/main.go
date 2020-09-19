package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/provideapp/ident/common"
	"github.com/provideapp/ident/token"
	"github.com/provideapp/vault/vault"

	provide "github.com/provideservices/provide-go/common"
)

const runloopSleepInterval = 250 * time.Millisecond
const runloopTickInterval = 5000 * time.Millisecond

var (
	cancelF     context.CancelFunc
	closing     uint32
	shutdownCtx context.Context
	sigs        chan os.Signal

	srv *http.Server
)

func init() {
	provide.RequireJWTVerifiers()
	provide.RequireGin()
}

func main() {
	common.Log.Debugf("starting vault API...")
	installSignalHandlers()

	runAPI()

	timer := time.NewTicker(runloopTickInterval)
	defer timer.Stop()

	for !shuttingDown() {
		select {
		case <-timer.C:
			// tick... no-op
		case sig := <-sigs:
			common.Log.Debugf("received signal: %s", sig)
			srv.Shutdown(shutdownCtx)
			shutdown()
		case <-shutdownCtx.Done():
			close(sigs)
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
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	shutdownCtx, cancelF = context.WithCancel(context.Background())
}

func shutdown() {
	if atomic.AddUint32(&closing, 1) == 1 {
		common.Log.Debug("shutting down vault API")
		cancelF()
	}
}

func runAPI() {
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())
	r.Use(provide.CORSMiddleware())

	r.GET("/status", statusHandler)

	r.Use(token.AuthMiddleware())
	r.Use(common.AccountingMiddleware())
	r.Use(common.RateLimitingMiddleware())
	r.Use(provide.TrackAPICalls())
	r.Use(vault.AuditLogMiddleware())

	vault.InstallAPI(r)

	srv = &http.Server{
		Addr:    provide.ListenAddr,
		Handler: r,
	}

	if provide.ServeTLS {
		go srv.ListenAndServeTLS(provide.CertificatePath, provide.PrivateKeyPath)
	} else {
		go srv.ListenAndServe()
	}

	common.Log.Debugf("listening on %s", provide.ListenAddr)
}

func statusHandler(c *gin.Context) {
	provide.Render(nil, 204, c)
}

func shuttingDown() bool {
	return (atomic.LoadUint32(&closing) > 0)
}
