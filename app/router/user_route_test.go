package router

import (
	"context"
	"reflect"
	"testing"

	"github.com/xtls/xray-core/common/net"
)

func TestUserRouteCatalog(t *testing.T) {
	r := new(Router)
	base := &RoutingRule{RuleTag: "routes", UserRouteList: &net.PortList{Range: []*net.PortRange{{From: 0, To: 2}, {From: 65535, To: 65535}}}, InboundTag: []string{"vm"}, UserEmail: []string{"regexp:^alice@"}}
	if err := r.Init(context.Background(), &Config{Rule: []*RoutingRule{base}}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	old := r.UserRouteRules()
	for _, bad := range []*net.PortRange{nil, {From: 4, To: 3}, {From: 0, To: 65536}} {
		if err := r.ReloadRules(&Config{Rule: []*RoutingRule{{UserRouteList: &net.PortList{Range: []*net.PortRange{bad}}}}}, false); err == nil {
			t.Fatal("invalid API route range accepted")
		}
		if r.UserRouteRules() != old {
			t.Fatal("failed reload changed published catalog")
		}
	}
	if got := old.ForUser("vm", "alice@test"); !reflect.DeepEqual(got, []uint16{0, 1, 2, 65535}) {
		t.Fatal(got)
	}
	if len(old.ForUser("other", "alice@test")) != 0 || len(old.ForUser("vm", "bob@test")) != 0 {
		t.Fatal("scope leaked")
	}
	base.UserRouteList.Range[0].To = 100
	if len(old.ForUser("vm", "alice@test")) != 4 {
		t.Fatal("snapshot mutated through config")
	}
	if err := r.ReloadRules(&Config{Rule: []*RoutingRule{{VlessRouteList: &net.PortList{Range: []*net.PortRange{{From: 7, To: 7}}}}}}, true); err != nil {
		t.Fatal(err)
	}
	if len(r.UserRouteRules().ForUser("vm", "alice@test")) != 4 {
		t.Fatal("legacy rule created aliases")
	}
	if err := r.RemoveRule("routes"); err != nil {
		t.Fatal(err)
	}
	if len(r.UserRouteRules().ForUser("vm", "alice@test")) != 0 || len(old.ForUser("vm", "alice@test")) != 4 {
		t.Fatal("removal/snapshot mismatch")
	}
}
