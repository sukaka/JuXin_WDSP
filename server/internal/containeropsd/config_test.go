// config_test.go 配置加载与白名单解析测试。
package containeropsd

import (
	"testing"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadConfigDefaults(t *testing.T) {
	cfg, err := LoadConfig(envMap(map[string]string{}))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.SocketPath != DefaultSocket {
		t.Fatalf("SocketPath = %q, want %q", cfg.SocketPath, DefaultSocket)
	}
	if cfg.DockerHost != DefaultDockerHost {
		t.Fatalf("DockerHost = %q, want %q", cfg.DockerHost, DefaultDockerHost)
	}
	if cfg.Project != "" {
		t.Fatalf("Project 默认应为空（fail-closed），实际 %q", cfg.Project)
	}
	if len(cfg.AllowedServices) != 0 {
		t.Fatalf("AllowedServices 默认应为空，实际 %v", cfg.AllowedServices)
	}
}

func TestLoadConfigFromEnv(t *testing.T) {
	cfg, err := LoadConfig(envMap(map[string]string{
		EnvSocket:          "/run/x/ops.sock",
		EnvDockerHost:      "unix:///run/docker.sock",
		EnvProject:         "jiuzhang-stage5",
		EnvAllowedServices: " api , gateway ,postgres ",
	}))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.SocketPath != "/run/x/ops.sock" || cfg.DockerHost != "unix:///run/docker.sock" {
		t.Fatalf("socket/docker host 解析错误: %+v", cfg)
	}
	if cfg.Project != "jiuzhang-stage5" {
		t.Fatalf("Project = %q", cfg.Project)
	}
	for _, s := range []string{"api", "gateway", "postgres"} {
		if !cfg.AllowedServices[s] {
			t.Fatalf("白名单缺少 %q: %v", s, cfg.AllowedServices)
		}
	}
}

func TestLoadConfigRejectsBadValues(t *testing.T) {
	cases := map[string]map[string]string{
		"相对 socket 路径":    {EnvSocket: "run/ops.sock"},
		"tcp docker host": {EnvDockerHost: "tcp://127.0.0.1:2375"},
		"非法白名单服务名":        {EnvAllowedServices: "api,evil;rm"},
		"白名单含斜杠":          {EnvAllowedServices: "../etc"},
	}
	for name, env := range cases {
		if _, err := LoadConfig(envMap(env)); err == nil {
			t.Fatalf("%s: 应拒绝 %+v", name, env)
		}
	}
}

func TestValidServiceName(t *testing.T) {
	for _, ok := range []string{"api", "gateway-2", "a.b_c", "A9"} {
		if !ValidServiceName(ok) {
			t.Fatalf("%q 应合法", ok)
		}
	}
	for _, bad := range []string{"", "-lead", "a b", "a/b", "a;b", string(make([]byte, 65))} {
		if ValidServiceName(bad) {
			t.Fatalf("%q 应非法", bad)
		}
	}
}
