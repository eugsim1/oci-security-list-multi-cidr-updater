package main

import (
	"reflect"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func TestCanonicalPrefix(t *testing.T) {
	got, err := canonicalPrefix(" 10.20.30.42/24 ")
	if err != nil {
		t.Fatal(err)
	}
	if got != "10.20.30.0/24" {
		t.Fatalf("got %q", got)
	}
}

func TestExpandIngressPreservesRuleAndOrdersReplacements(t *testing.T) {
	rules := []core.IngressSecurityRule{{
		Source:      common.String("0.0.0.0/0"),
		SourceType:  core.IngressSecurityRuleSourceTypeCidrBlock,
		Protocol:    common.String("6"),
		Description: common.String("SSH administration"),
		TcpOptions: &core.TcpOptions{
			DestinationPortRange: &core.PortRange{Min: common.Int(22), Max: common.Int(22)},
		},
	}}

	got, ops := expandIngressRules(
		"ocid", "region", rules,
		makeStringSet([]string{"0.0.0.0/0"}),
		[]string{"203.0.113.9/32", "10.0.0.0/8"},
		false,
	)

	if len(got) != 2 || len(ops) != 2 {
		t.Fatalf("got %d rules and %d operations", len(got), len(ops))
	}
	if *got[0].Source != "203.0.113.9/32" || *got[1].Source != "10.0.0.0/8" {
		t.Fatalf("unexpected replacement order: %s, %s", *got[0].Source, *got[1].Source)
	}
	for _, rule := range got {
		if *rule.Protocol != "6" || *rule.Description != "SSH administration" || *rule.TcpOptions.DestinationPortRange.Min != 22 {
			t.Fatalf("rule properties were not preserved: %#v", rule)
		}
	}
}

func TestExpandIngressSkipsServiceCIDRBlock(t *testing.T) {
	rules := []core.IngressSecurityRule{{
		Source:     common.String("all-fra-services-in-oracle-services-network"),
		SourceType: core.IngressSecurityRuleSourceTypeServiceCidrBlock,
		Protocol:   common.String("6"),
	}}
	got, ops := expandIngressRules("ocid", "region", rules, nil, []string{"203.0.113.9/32"}, true)
	if !reflect.DeepEqual(got, rules) || len(ops) != 0 {
		t.Fatalf("service CIDR rule should be unchanged")
	}
}

func TestExpansionIsIdempotentWhenOriginalCIDRIsRetained(t *testing.T) {
	rules := []core.IngressSecurityRule{
		{Source: common.String("10.0.0.0/8"), Protocol: common.String("6")},
		{Source: common.String("203.0.113.9/32"), Protocol: common.String("6")},
	}
	targets := makeStringSet([]string{"10.0.0.0/8"})
	replacements := []string{"203.0.113.9/32", "10.0.0.0/8"}

	got, _ := expandIngressRules("ocid", "region", rules, targets, replacements, false)
	if !reflect.DeepEqual(normalizedIngressSlice(got), normalizedIngressSlice(rules)) {
		t.Fatalf("second execution changed the effective rule collection: %#v", got)
	}
}

func TestExpandEgress(t *testing.T) {
	rules := []core.EgressSecurityRule{{
		Destination:     common.String("0.0.0.0/0"),
		DestinationType: core.EgressSecurityRuleDestinationTypeCidrBlock,
		Protocol:        common.String("all"),
	}}
	got, _ := expandEgressRules("ocid", "region", rules, makeStringSet([]string{"0.0.0.0/0"}), []string{"203.0.113.9/32", "192.0.2.0/24"})
	if len(got) != 2 || *got[0].Destination != "203.0.113.9/32" || *got[1].Destination != "192.0.2.0/24" {
		t.Fatalf("unexpected egress expansion: %#v", got)
	}
}

func TestUniqueStringsKeepsFirstOccurrence(t *testing.T) {
	got := uniqueStrings([]string{"current", "office", "current", "vpn"})
	want := []string{"current", "office", "vpn"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func normalizedIngressSlice(rules []core.IngressSecurityRule) []core.IngressSecurityRule {
	out := make([]core.IngressSecurityRule, len(rules))
	for i, rule := range rules {
		out[i] = normalizeIngress(rule)
	}
	return out
}
