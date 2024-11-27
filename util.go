package abke

import (
	"crypto/rand"

	bls "github.com/cloudflare/circl/ecc/bls12381"
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

func copyG2(g2 *bls.G2) *bls.G2 {
	ret := new(bls.G2)
	ret.SetBytes(g2.Bytes())
	return ret
}

func randomScalar() *bls.Scalar {
	z := new(bls.Scalar)
	err := z.Random(rand.Reader)
	if err != nil {
		mu.Fatalf("failed to generate a random scalar")
	}
	return z
}

func copyScalar(z *bls.Scalar) *bls.Scalar {
	ret := new(bls.Scalar)
	ret.Set(z)
	return ret
}
