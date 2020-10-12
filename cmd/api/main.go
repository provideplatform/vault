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
	unsealerkey, err := GetEnv("VAULT_SEAL_UNSEAL_KEY")
	if err != nil {
		return fmt.Errorf("vault not unsealed. Error: %s", err.Error())
	}

	err = vault.SetUnsealerKey(*unsealerkey)
	if err != nil {
		return err
	}

	common.Log.Debug("vault unsealed")
	return nil
}

// GetEnv gets environment data, including from docker secrets in-memory file system
func GetEnv(s string) (*string, error) {

	// first check if it exists
	if s == "" {
		return nil, fmt.Errorf("environment variable %s not found", s)
	}

	// then check if it's a docker secret
	if strings.HasPrefix(s, "/run/secrets") {
		data, err := ioutil.ReadFile(s)
		if err != nil {
			common.Log.Debugf("File reading error %s", err)
			return nil, err
		}
		returnData := string(data)
		return &returnData, nil
	}

	returnData := os.Getenv(s)
	return &returnData, nil
}

func statusHandler(c *gin.Context) {
	provide.Render(nil, 204, c)
}

func shuttingDown() bool {
	return (atomic.LoadUint32(&closing) > 0)
}
