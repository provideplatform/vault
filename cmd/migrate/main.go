/*
 * Copyright 2017-2022 Provide Technologies Inc.
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
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jinzhu/gorm"
	"github.com/provideplatform/vault/common"

	"github.com/golang-migrate/migrate"
	"github.com/golang-migrate/migrate/database/postgres"
	_ "github.com/golang-migrate/migrate/source/file"

	dbconf "github.com/kthomas/go-db-config"
)

const initIfNotExistsRetryInterval = time.Millisecond * 2500
const initIfNotExistsTimeout = time.Second * 10

func main() {
	cfg := dbconf.GetDBConfig()

	err := initIfNotExists(
		cfg,
		os.Getenv("DATABASE_SUPERUSER"),
		os.Getenv("DATABASE_SUPERUSER_PASSWORD"),
	)
	if err != nil && !strings.Contains(err.Error(), "exists") { // HACK -- could be replaced with query
		common.Log.Warningf("migration failed; %s", err.Error())
		panic(err)
	}

	dsn := fmt.Sprintf(
		"postgres://%s/%s?user=%s&password=%s&sslmode=%s",
		cfg.DatabaseHost,
		cfg.DatabaseName,
		url.QueryEscape(cfg.DatabaseUser),
		url.QueryEscape(cfg.DatabasePassword),
		cfg.DatabaseSSLMode,
	)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		common.Log.Warningf("migration failed; %s", err.Error())
		panic(err)
	}

	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		common.Log.Warningf("migration failed; %s", err.Error())
		panic(err)
	}

	m, err := migrate.NewWithDatabaseInstance("file://./ops/migrations", cfg.DatabaseName, driver)
	if err != nil {
		common.Log.Warningf("migration failed; %s", err.Error())
		panic(err)
	}

	err = m.Up()
	if err != nil && err != migrate.ErrNoChange {
		common.Log.Warningf("migration failed; %s", err.Error())
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
				common.Log.Debugf("migration failed; db connection not established; %s", err.Error())
			}

			if time.Now().Sub(startedAt) >= initIfNotExistsTimeout {
				ticker.Stop()
				common.Log.Panicf("migration failed; initIfNotExists timed out connecting to %s:%d", superuserCfg.DatabaseHost, superuserCfg.DatabasePort)
			}
		}

		if client != nil {
			defer client.Close()
			break
		}
	}

	if err != nil {
		common.Log.Warningf("migration failed on host: %s:%d; %s", superuserCfg.DatabaseHost, superuserCfg.DatabasePort, err.Error())
		return err
	}

	result := client.Exec(fmt.Sprintf("CREATE USER \"%s\" WITH SUPERUSER PASSWORD '%s'", cfg.DatabaseUser, cfg.DatabasePassword))
	err = result.Error
	if err != nil {
		common.Log.Debugf("failed to create db superuser during attempted migration: %s; %s; attempting without superuser privileges", cfg.DatabaseUser, err.Error())

		result = client.Exec(fmt.Sprintf("CREATE USER \"%s\" PASSWORD '%s'", cfg.DatabaseUser, cfg.DatabasePassword))
		err = result.Error
		if err != nil {
			common.Log.Warningf("migration failed; failed to create user: %s; %s", cfg.DatabaseUser, err.Error())
			return err
		}
	}

	if err == nil {
		result = client.Exec(fmt.Sprintf("CREATE DATABASE \"%s\" OWNER \"%s\"", cfg.DatabaseName, cfg.DatabaseUser))
		err = result.Error
		if err != nil {
			common.Log.Warningf("migration failed; failed to create database %s using user %s; %s", cfg.DatabaseName, cfg.DatabaseUser, err.Error())
			return err
		}
	}

	return nil
}
