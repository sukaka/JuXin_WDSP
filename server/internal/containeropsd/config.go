// Package containeropsd 容器运维 sidecar：全栈唯一持有 Docker socket 的组件，
// 经共享卷 Unix Socket 向管理后端提供白名单收敛的容器运维通道
// （状态/日志/启停/按锁定镜像更新）。设计契约见 docs/CONTAINER_OPS_DESIGN.md。
package containeropsd

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// 环境变量名
const (
	EnvSocket          = "CONTAINEROPS_SOCKET"
	EnvDockerHost      = "DOCKER_HOST"
	EnvProject         = "CONTAINEROPS_PROJECT"
	EnvAllowedServices = "CONTAINEROPS_ALLOWED_SERVICES"
)

// 默认值
const (
	DefaultSocket     = "/run/containerops/containerops.sock"
	DefaultDockerHost = "unix:///var/run/docker.sock"
)

// compose 标签键
const (
	LabelProject = "com.docker.compose.project"
	LabelService = "com.docker.compose.service"
	LabelImage   = "com.docker.compose.image"
)

// serviceNameRe 校验 compose 服务名（白名单项与请求路径参数共用同一口径）。
var serviceNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

// Config 是 containeropsd 的运行配置。
type Config struct {
	// SocketPath 监听 Unix Socket 路径（CONTAINEROPS_SOCKET）
	SocketPath string
	// DockerHost Docker Engine API 地址，仅支持 unix://（DOCKER_HOST）
	DockerHost string
	// Project 允许运维的 compose 项目名（CONTAINEROPS_PROJECT）；
	// 空 = 未显式配置，所有端点 fail-closed 返回 503
	Project string
	// AllowedServices 服务白名单（CONTAINEROPS_ALLOWED_SERVICES，逗号分隔）；
	// 空 = 拒绝一切控制/日志/列表动作（仅返回明确错误）
	AllowedServices map[string]bool
}

// LoadConfig 从环境变量加载配置（getenv 注入便于测试，生产传 os.Getenv）。
func LoadConfig(getenv func(string) string) (Config, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	cfg := Config{
		SocketPath:      getenv(EnvSocket),
		DockerHost:      getenv(EnvDockerHost),
		Project:         strings.TrimSpace(getenv(EnvProject)),
		AllowedServices: map[string]bool{},
	}
	if cfg.SocketPath == "" {
		cfg.SocketPath = DefaultSocket
	}
	if cfg.DockerHost == "" {
		cfg.DockerHost = DefaultDockerHost
	}
	if !strings.HasPrefix(cfg.SocketPath, "/") {
		return Config{}, fmt.Errorf("%s 必须为绝对路径: %q", EnvSocket, cfg.SocketPath)
	}
	if _, err := parseDockerHost(cfg.DockerHost); err != nil {
		return Config{}, err
	}
	for _, item := range strings.Split(getenv(EnvAllowedServices), ",") {
		name := strings.TrimSpace(item)
		if name == "" {
			continue
		}
		if !serviceNameRe.MatchString(name) {
			return Config{}, fmt.Errorf("%s 含非法服务名: %q", EnvAllowedServices, name)
		}
		cfg.AllowedServices[name] = true
	}
	return cfg, nil
}

// parseDockerHost 解析 DOCKER_HOST，仅放行 unix:// 方案（fail-closed：
// 不支持 tcp://，避免无 TLS 的 Docker API 暴露面）。
func parseDockerHost(host string) (socketPath string, err error) {
	path, ok := strings.CutPrefix(host, "unix://")
	if !ok || path == "" {
		return "", fmt.Errorf("DOCKER_HOST 仅支持 unix:// 方案: %q", host)
	}
	if !strings.HasPrefix(path, "/") {
		return "", fmt.Errorf("DOCKER_HOST socket 路径必须为绝对路径: %q", host)
	}
	return path, nil
}

// ValidServiceName 校验服务名格式（路径参数进入 Docker API 前的基本卫生检查）。
func ValidServiceName(name string) bool {
	return serviceNameRe.MatchString(name)
}
