FROM golang:1.15 AS builder

RUN mkdir -p /go/src/github.com/provideapp
ADD . /go/src/github.com/provideapp/vault

RUN mkdir ~/.ssh && cp /go/src/github.com/provideapp/vault/ops/keys/ident-id_rsa ~/.ssh/id_rsa && chmod 0600 ~/.ssh/id_rsa && ssh-keyscan -t rsa github.com >> ~/.ssh/known_hosts
RUN git clone git@github.com:provideapp/ident.git /go/src/github.com/provideapp/ident && cd /go/src/github.com/provideapp/ident
RUN rm -rf ~/.ssh && rm -rf /go/src/github.com/provideapp/vault/ops/keys && rm -rf /go/src/github.com/provideapp/vault/test

WORKDIR /go/src/github.com/provideapp/vault
RUN make build

FROM alpine

RUN apk add --no-cache bash curl libc6-compat

RUN mkdir -p /vault
WORKDIR /vault

COPY --from=builder /go/src/github.com/provideapp/vault/.bin /vault/.bin
COPY --from=builder /go/src/github.com/provideapp/vault/ops /vault/ops

EXPOSE 8080
ENTRYPOINT ["./ops/run_api.sh"]
