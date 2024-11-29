package main

import (
	"crypto/rand"
	"fmt"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/abke"
	"github.com/etclab/mu"
)

func randomG1() *bls.G1 {
	elem := new(bls.G1)
	input := make([]byte, 128)
	_, err := rand.Read(input)
	if err != nil {
		mu.Fatalf("failed to generate %d random bytes", len(input))
	}
	elem.Hash(input, nil)
	return elem
}

func main() {
	pp := abke.NewPublicParameters(4)
	ca := abke.NewCertificateAuthority(pp)
	mpk := ca.MPK()

	attrs := []bool{true, false, false, true}
	pk, sk := ca.GenCert(attrs)

	fmt.Printf("\nPublic Key:\n%v\n", pk)
	fmt.Printf("\nSecret Key:\n%v\n", sk)
	fmt.Printf("pk.Verify returned %v\n", pk.Verify(pp, mpk))

	// generate random plaintext
	pt := make([]*bls.G1, pp.NumAttrs*2)
	fmt.Println("Plaintext:")
	for i := 0; i < len(pt); i++ {
		pt[i] = randomG1()
		fmt.Printf("\t%d\n", i)
		fmt.Printf("\t\t%v\n", pt[i])
	}

	ct := abke.Encrypt(pp, pk, attrs, pt)
	dec := abke.Decrypt(pp, sk, attrs, ct)
	fmt.Printf("dec[0].IsEqual(pt[1]: %v\n", dec[0].IsEqual(pt[1]))
	fmt.Printf("dec[1].IsEqual(pt[2]: %v\n", dec[1].IsEqual(pt[2]))
	fmt.Printf("dec[2].IsEqual(pt[4]: %v\n", dec[2].IsEqual(pt[4]))
	fmt.Printf("dec[3].IsEqual(pt[7]: %v\n", dec[3].IsEqual(pt[7]))

	newPk, newSk := abke.Unlink(pp, pk, sk)
	mu.UNUSED(newPk)
	mu.UNUSED(newSk)
}
