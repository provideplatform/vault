package main

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jinzhu/gorm"
	"github.com/provideapp/vault/common"

	"github.com/golang-migrate/migrate"
	"github.com/golang-migrate/migrate/database/postgres"
	_ "github.com/golang-migrate/migrate/source/file"

	dbconf "github.com/kthomas/go-db-config"
)

const initIfNotExistsRetryInterval = time.Second * 5
const initIfNotExistsTimeout = time.Second * 30

func main() {
	cfg := dbconf.GetDBConfig()

	err := initIfNotExists(
		cfg,
		os.Getenv("DATABASE_SUPERUSER"),
		os.Getenv("DATABASE_SUPERUSER_PASSWORD"),
	)
	if err != nil && !strings.Contains(err.Error(), "exists") { // HACK -- could be replaced with query
		common.Log.Warningf("migrations failed; %s", err.Error())
		panic(err)
	}

	dsn := fmt.Sprintf(
		"postgres://%s/%s?user=%s&password=%s&sslmode=%s",
		cfg.DatabaseHost,
		cfg.DatabaseName,
		cfg.DatabaseUser,
		url.QueryEscape(cfg.DatabasePassword),
		cfg.DatabaseSSLMode,
	)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		common.Log.Warningf("migrations failed 1: %s", err.Error())
		panic(err)
	}

	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		common.Log.Warningf("migrations failed 2; %s", err.Error())
		panic(err)
	}

	m, err := migrate.NewWithDatabaseInstance("file://./ops/migrations", cfg.DatabaseName, driver)
	if err != nil {
		common.Log.Warningf("migrations failed 3: %s", err.Error())
		panic(err)
	}

	err = m.Up()
	if err != nil && err != migrate.ErrNoChange {
		common.Log.Warningf("migrations failed 4: %s", err.Error())
	}
}

func initIfNotExists(cfg *dbconf.DBConfig, superuser, password string) error {
	if superuser == "" || password == "" {
		return nil
	}

	superuserCfg := &dbconf.DBConfig{
		DatabaseName:     superuser,
		DatabaseHost:     cfg.DatabaseHost,
		DatabasePort:     cfg.DatabasePort,
		DatabaseUser:     superuser,
		DatabasePassword: password,
		DatabaseSSLMode:  cfg.DatabaseSSLMode,
	}

	var client *gorm.DB
	var err error

	ticker := time.NewTicker(initIfNotExistsRetryInterval)
	startedAt := time.Now()
	for {
		select {
		case <-ticker.C:
			client, err = dbconf.DatabaseConnectionFactory(superuserCfg)
			if err == nil {
				ticker.Stop()
				break
			} else {
				common.Log.Debugf("migrations db connection not established; %s", err.Error())
			}

			if time.Now().Sub(startedAt) >= initIfNotExistsTimeout {
				ticker.Stop()
				panic(fmt.Sprintf("migrations failed; initIfNotExists timed out connecting to %s:%d", superuserCfg.DatabaseHost, superuserCfg.DatabasePort))
			}
		}

		if client != nil {
			defer client.Close()
			break
		}
	}

	if err != nil {
		common.Log.Warningf("migrations failed 5: %s :debug: host name %s, port name %d", err.Error(), superuserCfg.DatabaseHost, superuserCfg.DatabasePort)
		return err
	}

	result := client.Exec(fmt.Sprintf("CREATE USER %s WITH SUPERUSER PASSWORD '%s'", cfg.DatabaseUser, cfg.DatabasePassword))
	if err != nil {
		common.Log.Warningf("migrations failed; failed to create user: %s; %s", err.Error(), cfg.DatabaseUser)
		return err
	}

	if err == nil {
		result = client.Exec(fmt.Sprintf("CREATE DATABASE %s OWNER %s", cfg.DatabaseName, cfg.DatabaseUser))
		err = result.Error
		if err != nil {
			common.Log.Warningf("migrations failed; failed to create database %s using user %s; %s", cfg.DatabaseName, cfg.DatabaseUser, err.Error())
			return err
		}
	}

	return nil
}
