package abke

import (
	bls "github.com/cloudflare/circl/ecc/bls12381"
)

type MasterKey struct {
	GKeyPair  *ElhKeyPair
	HKeyPair  *ElhKeyPair
	UKeyPair  *ElhKeyPair
	JKeyPairs []*ElhKeyPair
}

func NewMasterKey(pp *PublicParameters) *MasterKey {
	m := new(MasterKey)
	m.GKeyPair = NewElhKeyPair()
	m.HKeyPair = NewElhKeyPair()
	m.UKeyPair = NewElhKeyPair()

	m.JKeyPairs = make([]*ElhKeyPair, pp.NumAttrs)
	for i := 0; i < pp.NumAttrs; i++ {
		m.JKeyPairs[i] = NewElhKeyPair()
	}

	return m
}

type MSK struct {
	G  *bls.Scalar
	H  *bls.Scalar
	U  *bls.Scalar
	Js []*bls.Scalar
}

func (m *MasterKey) MSK() *MSK {
	msk := new(MSK)

	msk.G = copyScalar(m.GKeyPair.SecretKey)
	msk.H = copyScalar(m.HKeyPair.SecretKey)
	msk.U = copyScalar(m.UKeyPair.SecretKey)

	msk.Js = make([]*bls.Scalar, len(m.JKeyPairs))
	for i, j := range m.JKeyPairs {
		msk.Js[i] = copyScalar(j.SecretKey)
	}

	return msk
}

type MPK struct {
	G  *bls.G2
	H  *bls.G2
	U  *bls.G2
	Js []*bls.G2
}

func (m *MasterKey) MPK() *MPK {
	mpk := new(MPK)

	mpk.G = copyG2(m.GKeyPair.PublicKey)
	mpk.H = copyG2(m.HKeyPair.PublicKey)
	mpk.U = copyG2(m.UKeyPair.PublicKey)

	mpk.Js = make([]*bls.G2, len(m.JKeyPairs))
	for i, j := range m.JKeyPairs {
		mpk.Js[i] = copyG2(j.PublicKey)
	}

	return mpk
}

type PublicKey struct {
	g     *bls.G1
	h     *bls.G1
	u     *bls.G1
	gsig  *bls.G1
	hsig  *bls.G1
	usig  *bls.G1
	es    []*bls.G1
	esigs []*bls.G1
}

func NewPublicKey(pp *PublicParameters) *PublicKey {
	pk := new(PublicKey)
	pk.es = make([]*bls.G1, pp.NumAttrs)
	pk.esigs = make([]*bls.G1, pp.NumAttrs)
	return pk
}

// Vrfy, ase_homosig_vrfy
func (pk *PublicKey) Verify(pp *PublicParameters, mpk *MPK) bool {
	// g ∈ G\{1}
	if !pk.g.IsOnG1() || pk.g.IsIdentity() {
		return false
	}
	// h ∈ G\{1}
	if !pk.h.IsOnG1() || pk.h.IsIdentity() {
		return false
	}
	// u ∈ G\{1}
	if !pk.u.IsOnG1() || pk.u.IsIdentity() {
		return false
	}

	if !ElhVerify(mpk.G, pk.gsig, pk.g) {
		return false
	}
	if !ElhVerify(mpk.H, pk.hsig, pk.h) {
		return false
	}
	if !ElhVerify(mpk.U, pk.usig, pk.u) {
		return false
	}

	tmp := new(bls.G1)
	for i := 0; i < pp.NumAttrs; i++ {
		tmp.Add(pk.u, pk.es[i])
		if !ElhVerify(mpk.Js[i], pk.esigs[i], tmp) {
			return false
		}
	}

	return true
}

type SecretKey struct {
	rs []*bls.Scalar
}

func NewSecretKey(pp *PublicParameters) *SecretKey {
	sk := new(SecretKey)
	sk.rs = make([]*bls.Scalar, pp.NumAttrs)
	return sk
}

// Unlink, ase_homosig_unlink
func Unlink(pp *PublicParameters, pk *PublicKey, sk *SecretKey) (*PublicKey, *SecretKey) {
	newPk := NewPublicKey(pp)
	newSk := NewSecretKey(pp)

	r := randomScalar()

	newPk.g = new(bls.G1)
	newPk.g.ScalarMult(r, pk.g)
	newPk.gsig = new(bls.G1)
	newPk.gsig.ScalarMult(r, pk.gsig)

	newPk.h = new(bls.G1)
	newPk.h.ScalarMult(r, pk.h)
	newPk.hsig = new(bls.G1)
	newPk.hsig.ScalarMult(r, pk.hsig)

	newPk.u = new(bls.G1)
	newPk.u.ScalarMult(r, pk.u)
	newPk.usig = new(bls.G1)
	newPk.usig.ScalarMult(r, pk.usig)

	for i := 0; i < len(pk.es); i++ {
		newPk.es[i] = new(bls.G1)
		newPk.es[i].ScalarMult(r, pk.es[i])
		newPk.esigs[i] = new(bls.G1)
		newPk.es[i].ScalarMult(r, pk.esigs[i])
		newSk.rs[i] = copyScalar(sk.rs[i])
	}

	return newPk, newSk
}

type ElhKeyPair struct {
	SecretKey *bls.Scalar
	PublicKey *bls.G2
}

func NewElhKeyPair() *ElhKeyPair {
	kp := new(ElhKeyPair)
	kp.SecretKey = randomScalar()

	g2 := bls.G2Generator()
	kp.PublicKey = new(bls.G2)
	kp.PublicKey.ScalarMult(kp.SecretKey, g2)

	return kp
}

func (kp *ElhKeyPair) Sign(msg *bls.G1) *bls.G1 {
	return ElhSign(kp.SecretKey, msg)
}

func ElhSign(sk *bls.Scalar, msg *bls.G1) *bls.G1 {
	sig := new(bls.G1)
	sig.ScalarMult(sk, msg)
	return sig
}

func ElhVerify(pk *bls.G2, sig, msg *bls.G1) bool {
	g2 := bls.G2Generator()
	gt1 := bls.Pair(sig, g2)
	gt2 := bls.Pair(msg, pk)
	return gt1.IsEqual(gt2)
}
