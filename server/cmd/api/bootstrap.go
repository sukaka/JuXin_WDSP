package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/config"
	"github.com/jiuzhang-waf/server/internal/security"
	"github.com/jiuzhang-waf/server/internal/users"
)

type initialAdminBootstrapStore interface {
	HasRoleUsers(ctx context.Context, roleCode string) (bool, error)
	EnsureInitialRoleUser(ctx context.Context, roleCode string, u *users.User) (bool, error)
}

type initialAdminSpec struct {
	RoleCode        string
	DisplayName     string
	DefaultUsername string
	Username        string
	Password        string
}

type generatedInitialAdmin struct {
	DisplayName string
	RoleCode    string
	Username    string
	Password    string
}

func defaultInitialAdminSpecs(sec config.SecurityConfig) []initialAdminSpec {
	return []initialAdminSpec{
		{
			RoleCode:        authz.RoleSystemAdmin,
			DisplayName:     "系统管理员",
			DefaultUsername: "admin",
			Username:        sec.InitialAdminUsername,
			Password:        sec.InitialAdminPassword,
		},
		{
			RoleCode:        authz.RoleSecurityAdmin,
			DisplayName:     "运维管理员",
			DefaultUsername: "operadmin",
			Username:        sec.InitialOperAdminUsername,
			Password:        sec.InitialOperAdminPassword,
		},
		{
			RoleCode:        authz.RoleAuditAdmin,
			DisplayName:     "审计管理员",
			DefaultUsername: "auditor",
			Username:        sec.InitialAuditAdminUsername,
			Password:        sec.InitialAuditAdminPassword,
		},
	}
}

func generateInitialPassword(username string) (string, error) {
	lowerUser := strings.ToLower(username)
	for i := 0; i < 8; i++ {
		pwd, err := security.GenerateTemporaryPassword(16)
		if err != nil {
			return "", err
		}
		if len(lowerUser) < 3 || !strings.Contains(strings.ToLower(pwd), lowerUser) {
			return pwd, nil
		}
	}
	return security.GenerateTemporaryPassword(16)
}

// ensureInitialAdmins 启动时按三权内置角色缺失幂等初始化默认管理员账号：
//   - 系统管理员（SYSTEM_ADMIN，默认 admin）
//   - 运维管理员（SECURITY_ADMIN，默认 operadmin）
//   - 审计管理员（AUDIT_ADMIN，默认 auditor）
//
// 密码优先级：对应环境变量注入 > 生成 16 位强随机一次性临时密码（仅打印一次到 out/stdout，不写入结构化日志）。
// 全部默认开启首次登录强制改密；若目标角色下已有未删除用户或用户名已被占用则幂等跳过并告警，不阻塞服务启动。
func ensureInitialAdmins(ctx context.Context, store initialAdminBootstrapStore, cfg *config.Config, out io.Writer) error {
	var generatedAccounts []generatedInitialAdmin
	now := time.Now()

	for _, spec := range defaultInitialAdminSpecs(cfg.Security) {
		hasRoleUser, err := store.HasRoleUsers(ctx, spec.RoleCode)
		if err != nil {
			return fmt.Errorf("check role %s users: %w", spec.RoleCode, err)
		}
		if hasRoleUser {
			continue
		}

		username := strings.TrimSpace(spec.Username)
		if username == "" {
			username = spec.DefaultUsername
		}
		if err := users.ValidateUsername(username); err != nil {
			slog.Warn("skip initial admin creation: invalid username",
				"role", spec.RoleCode, "username", username, "error", err)
			continue
		}

		password := spec.Password
		generated := false
		if password == "" {
			password, err = generateInitialPassword(username)
			if err != nil {
				return fmt.Errorf("generate temporary password for %s: %w", spec.RoleCode, err)
			}
			generated = true
		}

		hash, err := security.HashPassword(password)
		if err != nil {
			return fmt.Errorf("hash password for %s: %w", spec.RoleCode, err)
		}

		user := &users.User{
			Username:           username,
			DisplayName:        spec.DisplayName,
			PasswordHash:       hash,
			Status:             users.StatusActive,
			MustChangePassword: true,
			PasswordChangedAt:  &now,
		}
		created, err := store.EnsureInitialRoleUser(ctx, spec.RoleCode, user)
		if err != nil {
			if errors.Is(err, users.ErrUsernameExists) {
				slog.Warn("skip initial admin creation: username already exists",
					"role", spec.RoleCode, "username", username)
				continue
			}
			return fmt.Errorf("create initial %s (%s): %w", spec.RoleCode, username, err)
		}
		if !created {
			continue
		}

		if generated {
			generatedAccounts = append(generatedAccounts, generatedInitialAdmin{
				DisplayName: spec.DisplayName,
				RoleCode:    spec.RoleCode,
				Username:    username,
				Password:    password,
			})
		} else {
			slog.Info("initial admin created from environment variable",
				"role", spec.RoleCode, "username", username)
		}
	}

	if len(generatedAccounts) > 0 && out != nil {
		// 仅打印一次到 stdout，不写入结构化日志，首次登录必须修改
		fmt.Fprintf(out, "\n")
		fmt.Fprintf(out, "╔══════════════════════════════════════════════════════════════╗\n")
		fmt.Fprintf(out, "║  九章WDSP 默认管理员已创建（仅此一次显示，请立即记录）        ║\n")
		fmt.Fprintf(out, "╠══════════════════════════════════════════════════════════════╣\n")
		for i, acc := range generatedAccounts {
			if i > 0 {
				fmt.Fprintf(out, "╟──────────────────────────────────────────────────────────────╢\n")
			}
			fmt.Fprintf(out, "║  角色: %s (%s)\n", acc.DisplayName, acc.RoleCode)
			fmt.Fprintf(out, "║  用户名: %s\n", acc.Username)
			fmt.Fprintf(out, "║  临时密码: %s\n", acc.Password)
		}
		fmt.Fprintf(out, "╠══════════════════════════════════════════════════════════════╣\n")
		fmt.Fprintf(out, "║  所有初始/临时密码首次登录均必须修改                          ║\n")
		fmt.Fprintf(out, "╚══════════════════════════════════════════════════════════════╝\n\n")
	}

	return nil
}
