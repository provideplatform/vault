#!/bin/bash

if hash golint 2>/dev/null
then
    echo 'Using golint...' # No version command or flag
else 
    echo 'Installing golint'
    go get -u golang.org/x/lint/golint
fi

# go vet
echo 'Running golint...'
golint
