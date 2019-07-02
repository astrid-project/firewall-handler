package main

import (
	"testing"

	"github.com/stretchr/testify/assert"

	k8sfirewall "github.com/SunSince90/polycube/src/components/k8s/utils/k8sfirewall"
)

func TestTemplate(t *testing.T) {
	ip := "10.10.10.10"
	irule := k8sfirewall.ChainRule{
		Src:    "10.10.10.10",
		Dst:    "11.11.11.11",
		Action: "forward",
		Sport:  20,
		Dport:  52,
	}
	in, e := buildConnectionRules(ip, irule)
	assert.Len(t, in, 1)
	assert.Len(t, e, 2)

	assert.Equal(t, in[0].Conntrack, "established")
	assert.Equal(t, e[0].Conntrack, "new")
	assert.Equal(t, e[1].Conntrack, "established")
	assert.Equal(t, in[0].Dst, ip)
	assert.Equal(t, in[0].Src, irule.Dst)
	assert.Equal(t, e[0].Src, ip)
	assert.Equal(t, e[0].Dst, irule.Dst)
	assert.Equal(t, e[1].Src, ip)
	assert.Equal(t, e[1].Dst, irule.Dst)

	erule := k8sfirewall.ChainRule{
		Src:    "12.12.12.12",
		Dst:    ip,
		Action: "forward",
		Sport:  20,
		Dport:  52,
	}
	in, e = buildConnectionRules(ip, erule)
	assert.Len(t, in, 2)
	assert.Len(t, e, 1)
}

func TestParseIP(t *testing.T) {
	ip := "-1.-1.-1.-1"
	parsed := parseIP(ip)
	assert.Equal(t, parsed, "")

	ip = "10.10.10.-1"
	parsed = parseIP(ip)
	assert.Equal(t, parsed, "10.10.10.0/24")

	ip = "10.10.-1.-1"
	parsed = parseIP(ip)
	assert.Equal(t, parsed, "10.10.0.0/16")
}
