package main

import (
	"fmt"

	"github.com/etclab/abke"
	"github.com/etclab/mu"
)

func main() {
	pp := abke.NewPublicParameters(4)
	ca := abke.NewCertificateAuthority(pp)

	attrs := []bool{true, false, false, true}
	pk, sk := ca.GenCert(attrs)

	mpk := ca.MPK()
	fmt.Printf("pk.Verify returned %v\n", pk.Verify(pp, mpk))

	newPk, newSk := abke.Unlink(pp, pk, sk)
	mu.UNUSED(newPk)
	mu.UNUSED(newSk)
}
