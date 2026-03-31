package api

import (
	"strings"
	"testing"

	routerService "github.com/xtls/xray-core/app/router/command"
)

func TestResolveBalancerInfoTags(t *testing.T) {
	tags, err := resolveBalancerInfoTags([]string{"balancer-a", "balancer-b"})
	if err != nil {
		t.Fatalf("resolveBalancerInfoTags returned error: %v", err)
	}

	if len(tags) != 2 || tags[0] != "balancer-a" || tags[1] != "balancer-b" {
		t.Fatalf("unexpected tags: %#v", tags)
	}
}

func TestResolveBalancerInfoTagsRequiresArgument(t *testing.T) {
	if _, err := resolveBalancerInfoTags(nil); err == nil {
		t.Fatal("expected an error for empty balancer tag list")
	}
}

func TestResolveBalancerOverrideTarget(t *testing.T) {
	target, err := resolveBalancerOverrideTarget([]string{"direct"}, false)
	if err != nil {
		t.Fatalf("resolveBalancerOverrideTarget returned error: %v", err)
	}
	if target != "direct" {
		t.Fatalf("unexpected target: %q", target)
	}
}

func TestResolveBalancerOverrideTargetRemoveMode(t *testing.T) {
	target, err := resolveBalancerOverrideTarget(nil, true)
	if err != nil {
		t.Fatalf("resolveBalancerOverrideTarget returned error: %v", err)
	}
	if target != "" {
		t.Fatalf("unexpected target in remove mode: %q", target)
	}
}

func TestResolveBalancerOverrideTargetRejectsInvalidArgs(t *testing.T) {
	testCases := []struct {
		name   string
		args   []string
		remove bool
	}{
		{name: "missing target", args: nil},
		{name: "extra targets", args: []string{"direct", "backup"}},
		{name: "remove with target", args: []string{"direct"}, remove: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := resolveBalancerOverrideTarget(testCase.args, testCase.remove); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestRenderBalancerInfoResultsWithMultipleTags(t *testing.T) {
	output := renderBalancerInfoResults([]balancerInfoResult{
		{
			Tag: "balancer-a",
			Balancer: &routerService.BalancerMsg{
				Override:        &routerService.OverrideInfo{Target: "direct"},
				PrincipleTarget: &routerService.PrincipleTargetInfo{Tag: []string{"direct", "proxy"}},
			},
		},
		{
			Tag: "balancer-b",
			Balancer: &routerService.BalancerMsg{
				PrincipleTarget: &routerService.PrincipleTargetInfo{Tag: []string{"backup"}},
			},
		},
	})

	for _, expected := range []string{
		"balancer-a:",
		"balancer-b:",
		"Selecting Override:",
		"direct",
		"proxy",
		"backup",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("output %q does not contain %q", output, expected)
		}
	}
}

func TestRenderBalancerInfoJSONWithMultipleTags(t *testing.T) {
	output, err := renderBalancerInfoJSON([]balancerInfoResult{
		{
			Tag: "balancer-a",
			Balancer: &routerService.BalancerMsg{
				Override: &routerService.OverrideInfo{Target: "direct"},
			},
		},
		{
			Tag: "balancer-b",
			Balancer: &routerService.BalancerMsg{
				PrincipleTarget: &routerService.PrincipleTargetInfo{Tag: []string{"proxy"}},
			},
		},
	})
	if err != nil {
		t.Fatalf("renderBalancerInfoJSON returned error: %v", err)
	}

	for _, expected := range []string{
		"\"tag\": \"balancer-a\"",
		"\"tag\": \"balancer-b\"",
		"\"balancer\":",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("output %q does not contain %q", output, expected)
		}
	}
}
