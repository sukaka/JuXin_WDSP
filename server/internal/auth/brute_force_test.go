package auth

import (
	"context"
	"testing"
)

// bruteForceCall 记录一次登录暴破告警回调。
type bruteForceCall struct {
	username    string
	sourceIP    string
	lockMinutes int
}

// TestLoginLockoutFiresBruteForceAlert 密码路径：连续失败达阈锁定时触发一次告警回调；
// 未达阈不触发；锁定后的再次登录（ACCOUNT_LOCKED 路径）不重复触发。
func TestLoginLockoutFiresBruteForceAlert(t *testing.T) {
	env := newTOTPTestEnv(t)
	env.addUser(t, "frank", "Passw0rd!2026", false)

	var calls []bruteForceCall
	env.svc.SetBruteForceAlertFunc(func(_ context.Context, username, sourceIP string, lockMinutes int) {
		calls = append(calls, bruteForceCall{username, sourceIP, lockMinutes})
	})

	ctx := context.Background()
	in := LoginInput{Username: "frank", Password: "wrong-password", SourceIP: "10.0.0.9"}

	// 前 4 次失败未达阈（MaxFailedAttempts=5）→ 不触发
	for i := 0; i < 4; i++ {
		if _, err := env.svc.Login(ctx, in); err != ErrInvalidCredentials {
			t.Fatalf("第 %d 次失败登录 err = %v, want ErrInvalidCredentials", i+1, err)
		}
	}
	if len(calls) != 0 {
		t.Fatalf("未达阈不应触发告警, got %d 次", len(calls))
	}

	// 第 5 次失败达阈锁定 → 触发一次，参数为账号/源 IP/锁定时长
	if _, err := env.svc.Login(ctx, in); err != ErrInvalidCredentials {
		t.Fatalf("第 5 次失败登录 err = %v, want ErrInvalidCredentials", err)
	}
	if len(calls) != 1 {
		t.Fatalf("锁定时应触发 1 次告警, got %d", len(calls))
	}
	if calls[0].username != "frank" || calls[0].sourceIP != "10.0.0.9" || calls[0].lockMinutes != 15 {
		t.Errorf("告警参数错误: %+v", calls[0])
	}

	// 锁定后再次登录（ACCOUNT_LOCKED 直接拒绝）→ 不重复触发
	if _, err := env.svc.Login(ctx, in); err != ErrAccountUnavailable {
		t.Fatalf("锁定后登录 err = %v, want ErrAccountUnavailable", err)
	}
	if len(calls) != 1 {
		t.Errorf("锁定后登录不应重复触发告警, got %d 次", len(calls))
	}
}

// TestTOTPLockoutFiresBruteForceAlert TOTP 路径：第二步验证连续失败达阈锁定同样触发。
func TestTOTPLockoutFiresBruteForceAlert(t *testing.T) {
	env := newTOTPTestEnv(t)
	u := env.addUser(t, "grace", "Passw0rd!2026", false)
	secret, _ := env.armTOTP(t, u)

	var calls []bruteForceCall
	env.svc.SetBruteForceAlertFunc(func(_ context.Context, username, sourceIP string, lockMinutes int) {
		calls = append(calls, bruteForceCall{username, sourceIP, lockMinutes})
	})

	ctx := context.Background()
	login, err := env.svc.Login(ctx, LoginInput{Username: "grace", Password: "Passw0rd!2026", SourceIP: "10.0.0.10"})
	if err != nil || !login.TOTPRequired {
		t.Fatalf("应签发 TOTP 挑战: login=%+v err=%v", login, err)
	}
	verifyIn := TOTPVerifyInput{ChallengeToken: login.ChallengeToken, Code: wrongTOTPCode(t, secret), SourceIP: "10.0.0.10"}
	for i := 0; i < 5; i++ {
		if _, err := env.svc.VerifyTOTPLogin(ctx, verifyIn); err != ErrTOTPInvalid {
			t.Fatalf("第 %d 次 TOTP 验证 err = %v, want ErrTOTPInvalid", i+1, err)
		}
	}
	if len(calls) != 1 {
		t.Fatalf("TOTP 失败锁定时应触发 1 次告警, got %d", len(calls))
	}
	if calls[0].username != "grace" || calls[0].sourceIP != "10.0.0.10" || calls[0].lockMinutes != 15 {
		t.Errorf("告警参数错误: %+v", calls[0])
	}
}

// TestLoginLockoutWithoutAlertFunc 未注入回调时锁定流程不受影响（装配缺省形态）。
func TestLoginLockoutWithoutAlertFunc(t *testing.T) {
	env := newTOTPTestEnv(t)
	env.addUser(t, "henry", "Passw0rd!2026", false)
	ctx := context.Background()
	in := LoginInput{Username: "henry", Password: "wrong-password"}
	for i := 0; i < 5; i++ {
		if _, err := env.svc.Login(ctx, in); err != ErrInvalidCredentials {
			t.Fatalf("第 %d 次失败登录 err = %v, want ErrInvalidCredentials", i+1, err)
		}
	}
	if _, err := env.svc.Login(ctx, in); err != ErrAccountUnavailable {
		t.Fatalf("锁定后登录 err = %v, want ErrAccountUnavailable", err)
	}
}
