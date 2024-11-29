package abke

import (
	"fmt"
	"strings"

	bls "github.com/cloudflare/circl/ecc/bls12381"
)

type Ciphertext struct {
	g   *bls.G1
	h   *bls.G1
	c2s []*bls.G1
}

func (ct *Ciphertext) String() string {
	sb := new(strings.Builder)

	fmt.Fprintf(sb, "{g: %v,\nh: %v,\nc2s: [\n", ct.g, ct.h)
	for i, c2 := range ct.c2s {
		fmt.Fprintf(sb, "\t[%d] %v,\n", i, c2)
	}
	fmt.Fprintf(sb, "}")

	return sb.String()
}

// Enc, ase_homosig_enc
// Note that len(plaintext) = 2 * numAttrs
func Encrypt(pp *PublicParameters, pk *PublicKey, attrs []bool, plaintext []*bls.G1) *Ciphertext {
	ct := new(Ciphertext)

	s := randomScalar()
	ct.g = new(bls.G1)
	ct.g.ScalarMult(s, pk.g)

	t := randomScalar()
	ct.h = new(bls.G1)
	ct.h.ScalarMult(t, pk.h)

	idx := 0
	tmp := new(bls.G1)
	ct.c2s = make([]*bls.G1, 2*pp.NumAttrs)
	for i := 0; i < pp.NumAttrs; i++ {
		if attrs[i] {
			idx = 2*i + 1
			tmp.ScalarMult(t, pk.es[i])
		} else {
			idx = 2 * i
			tmp.ScalarMult(s, pk.es[i])
		}
		ct.c2s[idx] = new(bls.G1)
		ct.c2s[idx].Add(plaintext[idx], tmp)
	}

	return ct
}

// Dec, ase_homosig_dec
func Decrypt(pp *PublicParameters, sk *SecretKey, attrs []bool, ct *Ciphertext) []*bls.G1 {
	tmp := new(bls.G1)

	pt := make([]*bls.G1, pp.NumAttrs)
	for i := 0; i < pp.NumAttrs; i++ {
		pt[i] = new(bls.G1)
		if attrs[i] {
			tmp.ScalarMult(sk.rs[i], ct.h)
			tmp.Neg()
			pt[i].Add(ct.c2s[2*i+1], tmp)
		} else {
			tmp.ScalarMult(sk.rs[i], ct.g)
			tmp.Neg()
			pt[i].Add(ct.c2s[2*i], tmp)
		}
	}

	return pt
}
