package com.jiuzhang.apisecurity;

import java.util.List;

public final class DecisionEngine {
    public Models.Action request(
        Models.ProtectionMode mode,
        List<Models.Finding> findings
    ) {
        return decide(mode, findings, false);
    }

    public Models.Action response(
        Models.ProtectionMode mode,
        List<Models.Finding> findings,
        boolean hasMaskPlan
    ) {
        return decide(mode, findings, hasMaskPlan);
    }

    private Models.Action decide(
        Models.ProtectionMode mode,
        List<Models.Finding> findings,
        boolean hasMaskPlan
    ) {
        if (mode == Models.ProtectionMode.OFF) return Models.Action.ALLOW;
        if (findings.stream().anyMatch(this::isRateLimit)) return Models.Action.RATE_LIMIT;
        if (mode == Models.ProtectionMode.PROTECT
            && findings.stream().anyMatch(this::isBlocking)) {
            return Models.Action.BLOCK;
        }
        if (mode == Models.ProtectionMode.PROTECT && hasMaskPlan) {
            return Models.Action.MASK_RESPONSE;
        }
        if (findings.stream().anyMatch(finding -> finding.severity() != Models.Severity.INFO)) {
            return Models.Action.OBSERVE;
        }
        return Models.Action.ALLOW;
    }

    private boolean isRateLimit(Models.Finding finding) {
        return finding.proposedAction() == Models.Action.RATE_LIMIT;
    }

    private boolean isBlocking(Models.Finding finding) {
        return finding.proposedAction() == Models.Action.BLOCK;
    }
}
