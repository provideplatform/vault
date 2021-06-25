FROM golang:1.15 AS builder

RUN mkdir -p /go/src/github.com/provideplatform
ADD . /go/src/github.com/provideplatform/vault

RUN mkdir ~/.ssh && cp /go/src/github.com/provideplatform/vault/ops/keys/ident-id_rsa ~/.ssh/id_rsa && chmod 0600 ~/.ssh/id_rsa && ssh-keyscan -t rsa github.com >> ~/.ssh/known_hosts
RUN git clone git@github.com:provideapp/ident.git /go/src/github.com/provideplatform/ident && cd /go/src/github.com/provideplatform/ident
RUN rm -rf ~/.ssh && rm -rf /go/src/github.com/provideplatform/vault/ops/keys && rm -rf /go/src/github.com/provideplatform/vault/test

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
