package http_test

import (
	"fmt"
	"testing"

	"github.com/xtls/xray-core/proxy/http"
)

// What the handshake used to do: read the config map with no lock at all.
func lookupInMap(accounts map[string]string, username, password string) bool {
	stored, found := accounts[username]
	if !found {
		return false
	}
	return stored == password
}

func buildAccounts(n int) map[string]string {
	accounts := make(map[string]string, n)
	for i := 0; i < n; i++ {
		accounts[fmt.Sprintf("user%03d_%d", 500+i/10, i%10)] = "password"
	}
	return accounts
}

// The sizes bracket what an inbound actually carries: a dozen accounts on a
// busy gateway, 1000 as a ceiling nobody is near.
func BenchmarkLookup(b *testing.B) {
	for _, n := range []int{13, 100, 1000} {
		accounts := buildAccounts(n)
		name := fmt.Sprintf("user%03d_%d", 500+(n-1)/10, (n-1)%10)

		b.Run(fmt.Sprintf("map/%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if !lookupInMap(accounts, name, "password") {
					b.Fatal("miss")
				}
			}
		})
		b.Run(fmt.Sprintf("validator/%d", n), func(b *testing.B) {
			v := http.NewAccountValidator(accounts)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if !v.Has(name, "password") {
					b.Fatal("miss")
				}
			}
		})
		b.Run(fmt.Sprintf("validator-parallel/%d", n), func(b *testing.B) {
			v := http.NewAccountValidator(accounts)
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if !v.Has(name, "password") {
						b.Fatal("miss")
					}
				}
			})
		})
	}
}
