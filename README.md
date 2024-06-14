# vault

[![Go Report Card](https://goreportcard.com/badge/github.com/provideplatform/vault)](https://goreportcard.com/report/github.com/provideplatform/vault)

Microservice for state-of-the-art key management with a focus on providing advanced privacy and messaging capabilities (i.e., zero-knowledge proofs, SNARK-friendly hash functions, double-ratchet algorithm, etc.) in a single enterprise-grade API.

## Usage

See the [vault API Reference](https://docs.provide.services/vault).

## Run your own vault with Docker

Requires [Docker](https://www.docker.com/get-started)

```shell
/ops/docker-compose up
```

## Build and run your own vault from source

Requires [GNU Make](https://www.gnu.org/software/make), [Go](https://go.dev/doc/install), [Postgres](https://www.postgresql.org/download), [Redis](https://redis.io/docs/getting-started/installation)

```shell
make run_local
```

## Executables

The project comes with several wrappers/executables found in the `cmd`
directory.

|  Command   | Description          |
|:----------:|----------------------|
| **`api`**  | Runs the API server. |
| `consumer` | Runs a consumer.     |
| `migrate`  | Runs migrations.     |
