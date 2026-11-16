package detectors

import (
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

const (
	objectEnumerationWindow          = time.Minute
	objectEnumerationMinObjects      = 8
	objectEnumerationMinSequence     = 3
	objectEnumerationHighCardinality = 16
	objectEnumerationMaxObjects      = 32
)

// ObjectEnumerationResult is a bounded, single-window observation. Only HMAC
// references are accepted by the store; a true Alert is emitted once per window.
type ObjectEnumerationResult struct {
	DistinctObjects int
	RequestCount    int
	SequentialSteps int
	Alert           bool
}

type objectEnumerationEntry struct {
	windowStart   time.Time
	objects       map[string]struct{}
	requestCount  int
	sequenceSteps int
	expectedNext  string
	reported      bool
}

type objectEnumerationTracker struct {
	mu      sync.Mutex
	entries *lru
	now     func() time.Time
}

func newObjectEnumerationTracker(capacity int, now func() time.Time) *objectEnumerationTracker {
	if now == nil {
		now = time.Now
	}
	return &objectEnumerationTracker{entries: newLRU(capacity), now: now}
}

var defaultObjectEnumerationTracker = newObjectEnumerationTracker(DefaultStoreCapacity, nil)

func (t *objectEnumerationTracker) observe(key, ref, nextRef string) ObjectEnumerationResult {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now().UTC()
	var entry *objectEnumerationEntry
	if value, ok := t.entries.get(key); ok {
		entry = value.(*objectEnumerationEntry)
	} else {
		entry = &objectEnumerationEntry{}
		t.entries.set(key, entry)
	}
	if entry.windowStart.IsZero() || now.Before(entry.windowStart) || now.Sub(entry.windowStart) >= objectEnumerationWindow {
		*entry = objectEnumerationEntry{windowStart: now, objects: map[string]struct{}{}}
	}
	entry.requestCount++
	_, seen := entry.objects[ref]
	if !seen {
		if len(entry.objects) < objectEnumerationMaxObjects {
			entry.objects[ref] = struct{}{}
		}
		if nextRef != "" && entry.expectedNext == ref {
			entry.sequenceSteps++
		}
	}
	entry.expectedNext = nextRef
	result := ObjectEnumerationResult{
		DistinctObjects: len(entry.objects),
		RequestCount:    entry.requestCount,
		SequentialSteps: entry.sequenceSteps,
	}
	result.Alert = !entry.reported && ((result.DistinctObjects >= objectEnumerationMinObjects && result.SequentialSteps >= objectEnumerationMinSequence) || result.DistinctObjects >= objectEnumerationHighCardinality)
	if result.Alert {
		entry.reported = true
	}
	return result
}

// CheckObjectEnumeration detects short-window access to many distinct objects.
// It requires a verified principal and an explicit path template or semantic
// identifier constraint. It is an OBSERVE signal, not a BOLA ownership verdict.
func CheckObjectEnumeration(ctx *dsctx.RequestContext, p *parser.Parsed, jwt *jwtverify.VerificationResult, identitySalt, endpointKey string, semanticIDPaths map[string]string) {
	if ctx == nil || p == nil || jwt == nil || jwt.Status != jwtverify.StatusVerified || strings.TrimSpace(jwt.VerifiedPrincipalID) == "" || endpointKey == "" {
		return
	}
	for _, ref := range objectRefs(p, semanticIDPaths) {
		if ref.source == "query" && !isObjectSemantic(semanticIDPaths["QUERY:"+ref.dim]) {
			continue
		}
		checkObjectEnumerationRef(ctx, ref, jwt.VerifiedPrincipalID, identitySalt, endpointKey)
	}
}

func checkObjectEnumerationRef(ctx *dsctx.RequestContext, ref objectRef, principalID, identitySalt, endpointKey string) {
	refHMAC := objectEnumerationHMAC(identitySalt, endpointKey, ref, ref.raw)
	nextHMAC := ""
	if ref.typ == "numeric" {
		if id, err := strconv.ParseInt(ref.raw, 10, 64); err == nil && id >= 0 && id < math.MaxInt64 {
			nextHMAC = objectEnumerationHMAC(identitySalt, endpointKey, ref, strconv.FormatInt(id+1, 10))
		}
	}
	key := "jwt:" + principalID + "|" + endpointKey + "|" + ref.source + ":" + ref.dim
	result := objectEnumerationObserve(ctx, key, refHMAC, nextHMAC)
	if !result.Alert {
		return
	}
	pattern, severity, message, score := "high_cardinality_object_access", "MEDIUM", "many distinct object identifiers accessed in a short window", 15
	if result.SequentialSteps >= objectEnumerationMinSequence {
		pattern, severity, message, score = "sequential_distinct_object_access", "HIGH", "sequential access across distinct object identifiers", 30
	}
	evidence := map[string]string{
		"object_ref":         refHMAC,
		"object_type":        ref.typ,
		"source":             ref.source,
		"pattern":            pattern,
		"distinct_objects":   strconv.Itoa(result.DistinctObjects),
		"request_count":      strconv.Itoa(result.RequestCount),
		"sequential_steps":   strconv.Itoa(result.SequentialSteps),
		"window_seconds":     strconv.Itoa(int(objectEnumerationWindow.Seconds())),
		"identity_assurance": "JWT_VERIFIED",
	}
	switch ref.source {
	case "path":
		evidence["segment"] = ref.dim
	case "query":
		evidence["param"] = ref.dim
	case "body":
		evidence["field"] = ref.dim
	}
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector: "resource_access", RuleID: "resource.object_enumeration",
		Category: "OBSERVE", Severity: severity, Message: message, Evidence: evidence,
		ScoreDelta: score, Confidence: 0.7,
	})
}

func objectEnumerationHMAC(identitySalt, endpointKey string, ref objectRef, raw string) string {
	switch ref.typ {
	case "numeric":
		if id, err := strconv.ParseInt(raw, 10, 64); err == nil {
			raw = strconv.FormatInt(id, 10)
		}
	case "uuid", "hex":
		raw = strings.ToLower(raw)
	}
	key := []byte("jiuzhang/wdsp-object-enumeration/v1\x00" + identitySalt)
	value := endpointKey + "\x00" + ref.source + "\x00" + ref.dim + "\x00" + ref.typ + "\x00" + raw
	return ObjectRefHMAC(key, value)
}
