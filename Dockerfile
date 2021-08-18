FROM golang:1.15 AS builder

RUN mkdir -p /go/src/github.com/provideplatform
ADD . /go/src/github.com/provideplatform/vault

WORKDIR /go/src/github.com/provideplatform/vault
RUN make build

FROM alpine

RUN apk add --no-cache bash curl libstdc++ libc6-compat

RUN mkdir -p /vault
WORKDIR /vault

COPY --from=builder /go/src/github.com/provideplatform/vault/.bin /vault/.bin
COPY --from=builder /go/src/github.com/provideplatform/vault/ops /vault/ops

EXPOSE 8080
ENTRYPOINT ["./ops/run_api.sh"]
