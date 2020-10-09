package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/provideapp/ident/common"
	"github.com/provideapp/ident/token"
	"github.com/provideapp/vault/vault"

	provide "github.com/provideservices/provide-go/common"
	util "github.com/provideservices/provide-go/common/util"
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
	util.RequireJWTVerifiers()
	util.RequireGin()
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
	r.Use(util.TrackAPICalls())
	r.Use(vault.AuditLogMiddleware())

	vault.InstallAPI(r)

	err := autoUnsealVault()
	if err != nil {
		common.Log.Warningf("error unsealing vault %s", err.Error())
	}

	srv = &http.Server{
		Addr:    util.ListenAddr,
		Handler: r,
	}

	if util.ServeTLS {
		go srv.ListenAndServeTLS(util.CertificatePath, util.PrivateKeyPath)
	} else {
		go srv.ListenAndServe()
	}

	common.Log.Debugf("listening on %s", util.ListenAddr)
}

func autoUnsealVault() error {
	unsealerkey := os.Getenv("VAULT_SEAL_UNSEAL_KEY")

	if unsealerkey == "" {
		return fmt.Errorf("no unseal key found - vault is sealed")
	}

	if strings.HasPrefix(unsealerkey, "/run/secrets") {
		common.Log.Debugf("unsealing via in-memory key")
		// we have an unsealer key stored in memory in the docker secrets location
		data, err := ioutil.ReadFile(unsealerkey)
		if err != nil {
			common.Log.Debugf("File reading error %s", err)
			return err
		}
		unsealerKeyText := string(data)
		err = vault.SetUnsealerKey(unsealerKeyText)
		if err != nil {
			return err
		}

		common.Log.Debug("vault unsealed")
		return nil
	}

	common.Log.Debug("unsealing with environment variable - INSECURE")
	// if the environment var is not an empty string, check if we have the actual unsealer key in the environment variables
	err := vault.SetUnsealerKey(unsealerkey)
	if err != nil {
		return err
	}
	common.Log.Debug("vault unsealed")
	return nil
}

func statusHandler(c *gin.Context) {
	provide.Render(nil, 204, c)
}

func shuttingDown() bool {
	return (atomic.LoadUint32(&closing) > 0)
}
