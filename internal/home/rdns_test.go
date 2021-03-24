package home

import (
	"net"
	"testing"

	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/AdGuardHome/internal/aghtest"
	"github.com/AdguardTeam/AdGuardHome/internal/dnsforward"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRDNS_Resolve(t *testing.T) {
	ups := &aghtest.TestUpstream{
		Reverse: map[string][]string{
			"1.1.1.1.in-addr.arpa.":     {"one.one.one.one"},
			"1.1.168.192.in-addr.arpa.": {"local.domain"},
		},
	}
	dns := dnsforward.NewCustomServer(&proxy.Proxy{
		Config: proxy.Config{
			UpstreamConfig: &proxy.UpstreamConfig{
				Upstreams: []upstream.Upstream{ups},
			},
		},
	})

	clients := &clientsContainer{}

	ipd, err := aghnet.NewIPDetector()
	require.NoError(t, err)

	lr := &aghtest.LocalResolvers{
		Ups: ups,
	}
	rdns := NewRDNS(dns, clients, ipd, lr)

	testCases := []struct {
		name string
		want string
		req  net.IP
	}{{
		name: "external",
		want: "one.one.one.one",
		req:  net.IP{1, 1, 1, 1},
	}, {
		name: "local",
		want: "local.domain",
		req:  net.IP{192, 168, 1, 1},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r, rerr := rdns.resolve(tc.req)
			require.Nil(t, rerr)
			assert.Equal(t, tc.want, r)
		})
	}
}
