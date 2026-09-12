package securityevents

import "testing"

func TestApplyProtectRecommendation(t *testing.T) {
	confirmed := 19.0 / 20.0
	fp := 1.0 / 20.0
	stat := RuleEffectStat{Reviewed: 20, ConfirmationRate: &confirmed, FPRate: &fp}
	applyProtectRecommendation(&stat)
	if !stat.ProtectRecommendation {
		t.Fatal("expected a protect recommendation at the configured thresholds")
	}
	if stat.ProtectRecommendationReason == "" {
		t.Fatal("expected an explainable recommendation reason")
	}
}

func TestApplyProtectRecommendationRequiresConservativeThresholds(t *testing.T) {
	confirmed := 19.0 / 20.0
	fp := 1.0 / 20.0
	stat := RuleEffectStat{Reviewed: 19, ConfirmationRate: &confirmed, FPRate: &fp}
	applyProtectRecommendation(&stat)
	if stat.ProtectRecommendation {
		t.Fatal("must not recommend before the minimum reviewed count")
	}

	confirmed = 0.8
	fp = 0.051
	stat = RuleEffectStat{Reviewed: 20, ConfirmationRate: &confirmed, FPRate: &fp}
	applyProtectRecommendation(&stat)
	if stat.ProtectRecommendation {
		t.Fatal("must not recommend when the false-positive rate is above the threshold")
	}
}
