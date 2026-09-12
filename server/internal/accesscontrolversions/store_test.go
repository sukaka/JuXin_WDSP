package accesscontrolversions

import "testing"

func TestPublishResultTransitionAllowed(t *testing.T) {
	tests := []struct {
		name          string
		current, next string
		want          bool
	}{
		{name: "pending to success", current: PublishPending, next: PublishSuccess, want: true},
		{name: "pending to failed", current: PublishPending, next: PublishFailed, want: true},
		{name: "pending retry", current: PublishPending, next: PublishPending, want: true},
		{name: "success idempotent", current: PublishSuccess, next: PublishSuccess, want: true},
		{name: "failed idempotent", current: PublishFailed, next: PublishFailed, want: true},
		{name: "success cannot become failed", current: PublishSuccess, next: PublishFailed, want: false},
		{name: "failed cannot become success", current: PublishFailed, next: PublishSuccess, want: false},
		{name: "success cannot become pending", current: PublishSuccess, next: PublishPending, want: false},
		{name: "unknown state cannot transition", current: "BROKEN", next: PublishSuccess, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := publishResultTransitionAllowed(tt.current, tt.next); got != tt.want {
				t.Fatalf("publishResultTransitionAllowed(%q, %q) = %v, want %v", tt.current, tt.next, got, tt.want)
			}
		})
	}
}
