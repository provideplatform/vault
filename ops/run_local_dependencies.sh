#!/bin/bash

if hash psql 2>/dev/null
then
    echo 'Using' `psql --version`
else
    echo 'Installing postgresql'
    sudo apt-get update
    sudo apt-get -y install postgresql
fi

if [[ -z "${DATABASE_PORT}" ]]; then
  DATABASE_PORT=5432
fi

pg_ctl -D /usr/local/var/postgres -p ${DATABASE_PORT} start > /dev/null 2>&1 &
