package abke

import (
	bls "github.com/cloudflare/circl/ecc/bls12381"
)

type CertificateAuthority struct {
	pp *PublicParameters
	mk *MasterKey
}

// Setup
func NewCertificateAuthority(pp *PublicParameters) *CertificateAuthority {
	ca := new(CertificateAuthority)
	ca.pp = pp
	ca.mk = NewMasterKey(pp)
	return ca
}

func (ca *CertificateAuthority) MPK() *MPK {
	return ca.mk.MPK()
}

// GenCert,  ase_homosig_gen()
func (ca *CertificateAuthority) GenCert(attrs []bool) (*PublicKey, *SecretKey) {
	pk := NewPublicKey(ca.pp)
	sk := NewSecretKey(ca.pp)

	pk.g = randomG1()
	pk.h = randomG1()
	pk.u = randomG1()

	pk.gsig = ca.mk.GKeyPair.Sign(pk.g)
	pk.hsig = ca.mk.HKeyPair.Sign(pk.h)
	pk.usig = ca.mk.UKeyPair.Sign(pk.u)

	tmp := new(bls.G1)
	for i := 0; i < ca.pp.NumAttrs; i++ {
		sk.rs[i] = randomScalar()
		pk.es[i] = new(bls.G1)
		if attrs[i] {
			pk.es[i].ScalarMult(sk.rs[i], pk.h)
		} else {
			pk.es[i].ScalarMult(sk.rs[i], pk.g)
		}

		tmp.Add(pk.es[i], pk.u)
		pk.esigs[i] = ca.mk.JKeyPairs[i].Sign(tmp)
	}

	return pk, sk
}
