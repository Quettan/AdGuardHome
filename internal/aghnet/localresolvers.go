// This is not the best place for this functionality, but since we need to use
// it in both rDNS (home) and dnsServer (dnsforward) we put it here.

package aghnet

import (
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/agherr"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
)

// LocalResolvers is used to perform exchanging PTR requests for addresses from
// locally-served networks.
//
// TODO(e.burkov): Maybe expand with method like ExchangeParallel to be able to
// use user's upstream mode settings.
type LocalResolvers interface {
	Exchange(req *dns.Msg) (resp *dns.Msg, err error)
}

// localResolvers is the default implementation of LocalResolvers interface.
type localResolvers struct {
	ups []upstream.Upstream
}

// NewLocalResolvers creates a LocalResolvers instance from passed local
// resolvers addresses.  It returns an error if any of addrs failed to become an
// upstream.
func NewLocalResolvers(addrs []string, timeout time.Duration) (lr LocalResolvers, err error) {
	defer agherr.Annotate("localResolvers: %w", &err)

	if len(addrs) == 0 {
		return &localResolvers{ups: nil}, nil
	}

	var ups []upstream.Upstream
	for _, addr := range addrs {
		var u upstream.Upstream
		u, err = upstream.AddressToUpstream(addr, upstream.Options{Timeout: timeout})
		if err != nil {
			return nil, err
		}

		ups = append(ups, u)
	}

	return &localResolvers{ups: ups}, nil
}

// Exсhange performs a query to each resolver until first response.
func (lr *localResolvers) Exchange(req *dns.Msg) (resp *dns.Msg, err error) {
	defer agherr.Annotate("localResolvers", &err)

	var errs []error
	for _, u := range lr.ups {
		resp, err = u.Exchange(req)
		if err != nil {
			errs = append(errs, err)

			continue
		}

		if resp != nil {
			return resp, nil
		}
	}

	return nil, agherr.Many("can't exchange", errs...)
}
