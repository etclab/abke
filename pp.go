package abke

import (
	"github.com/etclab/mu"
)

type PublicParameters struct {
	NumAttrs int // m
}

func NewPublicParameters(numAttrs int) *PublicParameters {
	if numAttrs <= 0 {
		mu.Fatalf("numAttrs must be > 0")
	}

	pp := new(PublicParameters)
	pp.NumAttrs = numAttrs
	return pp
}
