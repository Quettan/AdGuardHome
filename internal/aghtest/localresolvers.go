package aghtest

import (
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
)

// LocalResolvers is an implementor aghnet.LocalResolvers interface to
// simplify testing.
type LocalResolvers struct {
	Ups upstream.Upstream
}

// Exchange implements aghnet.LocalResolvers interface for *LocalResolvers.
func (lr *LocalResolvers) Exchange(req *dns.Msg) (resp *dns.Msg, err error) {
	if lr.Ups == nil {
		lr.Ups = &TestErrUpstream{}
	}

	return lr.Ups.Exchange(req)
}
