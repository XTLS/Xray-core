package api

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"google.golang.org/grpc"

	"github.com/xtls/xray-core/app/router"
	routerService "github.com/xtls/xray-core/app/router/command"
	"github.com/xtls/xray-core/main/commands/base"
)

func TestAddRulesConfigFiles(t *testing.T) {
	serverAddr, timeout, jsonOutput := apiServerAddrPtr, apiTimeout, apiJSON
	t.Cleanup(func() { apiServerAddrPtr, apiTimeout, apiJSON = serverAddr, timeout, jsonOutput })

	for _, tc := range []struct {
		name   string
		append bool
		files  int
		want   []string
	}{
		{"replace multiple files", false, 2, []string{"first", "second"}},
		{"append multiple files", true, 2, []string{"old", "first", "second"}},
		{"replace single file", false, 1, []string{"first"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := new(router.Router)
			if err := r.Init(context.Background(), &router.Config{Rule: []*router.RoutingRule{{
				TargetTag: &router.RoutingRule_Tag{Tag: "old"}, RuleTag: "old", InboundTag: []string{"old"},
			}}}, nil, nil, nil); err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			server := grpc.NewServer()
			routerService.RegisterRoutingServiceServer(server, routerService.NewRoutingServer(r, nil))
			stopped := make(chan struct{})
			go func() {
				defer close(stopped)
				server.Serve(listener)
			}()
			t.Cleanup(func() { server.Stop(); <-stopped })

			args := []string{"--server=" + listener.Addr().String()}
			if tc.append {
				args = append(args, "--append")
			}
			dir := t.TempDir()
			for _, tag := range []string{"first", "second"}[:tc.files] {
				path := filepath.Join(dir, tag+".json")
				config := fmt.Sprintf(`{"routing":{"rules":[{"type":"field","inboundTag":[%q],"outboundTag":%q,"ruleTag":%q}]}}`, tag, tag, tag)
				if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
					t.Fatal(err)
				}
				args = append(args, path)
			}
			executeAddRules(&base.Command{}, args)

			var got []string
			for _, rule := range r.ListRule() {
				got = append(got, rule.GetRuleTag())
				if rule.GetOutboundTag() != rule.GetRuleTag() {
					t.Errorf("rule %q has outbound %q", rule.GetRuleTag(), rule.GetOutboundTag())
				}
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("rule order = %v, want %v", got, tc.want)
			}
		})
	}
}
