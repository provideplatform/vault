package main

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestMigrations(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Vault Migrations Suite")
}

var _ = Describe("Main", func() {

})
