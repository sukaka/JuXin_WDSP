package apiruntime

const (
	traceIDLen     = 32
	allZeroTraceID = "00000000000000000000000000000000"
)

func normalizeTraceID(traceID string) string {
	if len(traceID) != traceIDLen || traceID == allZeroTraceID || !isLowerHex(traceID) {
		return ""
	}
	return traceID
}
