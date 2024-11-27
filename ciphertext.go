package abke

import (
	bls "github.com/cloudflare/circl/ecc/bls12381"
)

type Ciphertext struct {
	g   *bls.G1
	h   *bls.G1
	c2s []*bls.G1
}

// Enc, ase_homosig_enc
func Encrypt(pp *PublicParameters, pk *PublicKey, attrs []bool, plaintext []*bls.G1) *Ciphertext {
	ct := new(Ciphertext)

	s := randomScalar()
	t := randomScalar()

	ct.g = new(bls.G1)
	ct.g.ScalarMult(s, pk.g)

	ct.h = new(bls.G1)
	ct.h.ScalarMult(t, pk.h)

	idx := 0
	ct.c2s = make([]*bls.G1, 2*pp.NumAttrs)
	for i := 0; i < pp.NumAttrs; i++ {
		if attrs == nil || !attrs[i] {
			idx = 2 * i
			ct.c2s[idx] = new(bls.G1)
			ct.c2s[idx].ScalarMult(s, pk.es[i])
			ct.c2s[idx].Add(ct.c2s[idx], plaintext[idx])
		}
		if attrs == nil || attrs[i] {
			idx = 2*i + 1
			ct.c2s[idx] = new(bls.G1)
			ct.c2s[idx].ScalarMult(t, pk.es[i])
			ct.c2s[idx].Add(ct.c2s[idx], plaintext[idx])
		}
	}

	return ct
}

// Dec, ase_homosig_dec
func Decrypt(pp *PublicParameters, sk *SecretKey, attrs []bool, ct *Ciphertext) []*bls.G1 {
	pt := make([]*bls.G1, pp.NumAttrs)

	for i := 0; i < pp.NumAttrs; i++ {
		pt[i] = new(bls.G1)
		if !attrs[i] {
			pt[i].ScalarMult(sk.rs[i], ct.g)
			pt[i].Neg()
			pt[i].Add(pt[i], ct.c2s[2*i])
		} else {
			pt[i].ScalarMult(sk.rs[i], ct.h)
			pt[i].Neg()
			pt[i].Add(pt[i], ct.c2s[2*i+1])
		}
	}

	return pt
}

// TODO: Unlink, ase_homosig_unlink
