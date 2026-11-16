package behaviorstore

import (
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
	"github.com/jiuzhang-waf/gateway/dynamic_security/pipeline"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/counters"
	"go.uber.org/zap"
)

const objectEnumerationValkeyImage = "valkey/valkey:8.1.8-alpine@sha256:94365b275456ae14621001c03556c732b1d93a0cdeacc317d1bdd52eba680885"

func objectEnumerationValkey(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker unavailable; real Valkey integration not run")
	}
	name := fmt.Sprintf("jz-object-enum-it-%d", time.Now().UnixNano())
	cmd := exec.Command("docker", "run", "-d", "--rm", "--name", name, "-p", "127.0.0.1:0:6379", objectEnumerationValkeyImage)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("start isolated Valkey: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	out, err := exec.Command("docker", "port", name, "6379/tcp").Output()
	if err != nil {
		t.Fatalf("Valkey mapped port: %v", err)
	}
	addr := strings.TrimSpace(strings.Split(string(out), "\n")[0])
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		addr = "127.0.0.1" + addr[i:]
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return addr
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("isolated Valkey did not become ready")
	return ""
}

func TestObjectEnumerationRealValkey(t *testing.T) {
	addr := objectEnumerationValkey(t)
	newClient := func() counters.ValkeyClient {
		cli, err := counters.NewValkeyClient(counters.ValkeyConfig{Address: addr})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cli.Close() })
		return cli
	}
	prefix := "test:objenum:" + counters.HashParts(t.Name(), time.Now().String())

	t.Run("shared window and expiry", func(t *testing.T) {
		clk := &testClock{now: baseTime}
		nodeA := New(newClient(), prefix, 0, zap.NewNop())
		nodeB := New(newClient(), prefix, 0, zap.NewNop())
		nodeA.now, nodeB.now = clk.Now, clk.Now
		key := t.Name()
		var last detectors.ObjectEnumerationResult
		for i := 0; i < detectors.ObjectEnumerationMinObjects; i++ {
			node := nodeA
			if i%2 == 1 {
				node = nodeB
			}
			last = node.ObserveObject(key, enumerationRef(i), enumerationRef(i+1))
		}
		want := detectors.ObjectEnumerationResult{DistinctObjects: 8, RequestCount: 8, SequentialSteps: 7, Alert: true}
		if last != want {
			t.Fatalf("real shared window: got=%+v want=%+v", last, want)
		}
		clk.Advance(detectors.ObjectEnumerationWindow)
		if got := nodeB.ObserveObject(key, enumerationRef(8), enumerationRef(9)); got.Alert || got.DistinctObjects != 1 || got.RequestCount != 1 {
			t.Fatalf("real window did not expire: %+v", got)
		}
	})

	t.Run("atomic concurrent observations", func(t *testing.T) {
		nodeA := New(newClient(), prefix, 0, zap.NewNop())
		nodeB := New(newClient(), prefix, 0, zap.NewNop())
		var alerts atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 64; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				node := nodeA
				if i%2 == 1 {
					node = nodeB
				}
				if node.ObserveObject(t.Name(), enumerationRef(i%detectors.ObjectEnumerationHighCardinality), "").Alert {
					alerts.Add(1)
				}
			}(i)
		}
		wg.Wait()
		if alerts.Load() != 1 {
			t.Fatalf("real shared window alert count=%d", alerts.Load())
		}
		result := nodeA.ObserveObject(t.Name(), enumerationRef(0), "")
		if result.RequestCount != 65 || result.DistinctObjects != detectors.ObjectEnumerationHighCardinality {
			t.Fatalf("real atomic count mismatch: %+v", result)
		}
	})

	t.Run("API pipeline across nodes", func(t *testing.T) {
		nodeA := New(newClient(), prefix, 0, zap.NewNop())
		nodeB := New(newClient(), prefix, 0, zap.NewNop())
		for i := 0; i < detectors.ObjectEnumerationMinObjects; i++ {
			node := nodeA
			if i%2 == 1 {
				node = nodeB
			}
			req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://h/v1/cases/%d", 9600+i), nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer unit-test-credential-0123456789")
			res, err := pipeline.Process(req, pipeline.Config{
				Enabled: true, Mode: "PROTECT", ApplicationID: "app-it", IdentitySalt: "unit-test-salt",
				JWTVerification: &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "verified-subject-fingerprint"},
				Stores:          node.Overrides(),
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if res.FinalAction == "BLOCK" {
				t.Fatalf("observation must not block: %+v", res.Context.CopyMatches())
			}
			if i != detectors.ObjectEnumerationMinObjects-1 {
				continue
			}
			found := false
			for _, match := range res.Context.CopyMatches() {
				if match.RuleID == "resource.object_enumeration" {
					found = true
					if match.Category != "OBSERVE" || match.Evidence["distinct_objects"] != "8" || !strings.HasPrefix(match.Evidence["object_ref"], "objref:") {
						t.Fatalf("unexpected pipeline evidence: %+v", match)
					}
				}
			}
			if !found {
				t.Fatalf("cross-node API pipeline did not detect enumeration: %+v", res.Context.CopyMatches())
			}
		}
	})
}
