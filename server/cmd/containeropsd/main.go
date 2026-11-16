// containeropsd 容器运维 sidecar 入口：全栈唯一挂载 docker.sock 的组件，
// 经共享卷 Unix Socket 向管理后端提供白名单收敛的容器运维通道。
// 配置经环境变量注入：CONTAINEROPS_SOCKET / DOCKER_HOST / CONTAINEROPS_PROJECT /
// CONTAINEROPS_ALLOWED_SERVICES（契约见 docs/CONTAINER_OPS_DESIGN.md）。
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jiuzhang-waf/server/internal/containeropsd"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "containeropsd: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg, err := containeropsd.LoadConfig(os.Getenv)
	if err != nil {
		return err
	}
	if cfg.Project == "" {
		// fail-closed：未显式配置项目时进程照常运行，但所有端点返回 503
		logger.Warn("CONTAINEROPS_PROJECT 未配置，所有端点将 fail-closed 返回 503")
	}
	if len(cfg.AllowedServices) == 0 {
		logger.Warn("CONTAINEROPS_ALLOWED_SERVICES 为空，列表为空且控制动作将被拒绝")
	}

	docker, err := containeropsd.NewDockerClient(cfg.DockerHost)
	if err != nil {
		return err
	}
	// 启动探测仅告警不退出：Engine 可能稍后恢复，请求期错误按 503 如实返回
	pingCtx, pingCancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := docker.Ping(pingCtx); err != nil {
		logger.Warn("Docker Engine 探测失败（将继续运行，请求期按 503 返回）", "error", err)
	}
	pingCancel()

	svc, err := containeropsd.NewService(cfg, docker, logger)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return svc.Run(ctx)
}
