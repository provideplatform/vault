#!/bin/bash

if [ ! -d "${GOPATH}/src/github.com/ethereum" ] ; then
  git clone https://github.com/ethereum/go-ethereum "${GOPATH}/src/github.com/ethereum/go-ethereum"
  cp -r "${GOPATH}/src/github.com/ethereum/go-ethereum/crypto/secp256k1/libsecp256k1" "./vendor/github.com/ethereum/go-ethereum/crypto/secp256k1"
fi

if [ ! -d "./vendor/github.com/herumi/bls-eth-go-binary/bls/include" ] ; then
  git clone -b release https://github.com/herumi/bls-eth-go-binary "${GOPATH}/src/github.com/herumi/bls-eth-go-binary"
#   mkdir -p "./vendor/github.com/herumi/bls-eth-go-binary/bls/include"
#   mkdir -p "./vendor/github.com/herumi/bls-eth-go-binary/bls/lib"
  cp -r "${GOPATH}/src/github.com/herumi/bls-eth-go-binary/bls/include" "./vendor/github.com/herumi/bls-eth-go-binary/bls"
    cp -r "${GOPATH}/src/github.com/herumi/bls-eth-go-binary/bls/lib" "./vendor/github.com/herumi/bls-eth-go-binary/bls"
fi
