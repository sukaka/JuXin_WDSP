// update.go 容器更新：目标镜像取 compose label com.docker.compose.image（缺省当前
// Config.Image），显式拒绝 latest 与裸仓库名；尝试 pull（离线失败可容忍），比对镜像 ID，
// 有变化时按 inspect 的 Config/HostConfig/Networking 重建（保留卷/端口/网络/环境），
// 健康等待，失败回滚旧容器。全程不输出环境变量值。
package containeropsd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// pinnedRefRe 显式锁定的镜像引用：name:tag 或 name:tag@sha256:<digest>。
// 仓库名小写（允许 registry 端口与多级路径），tag 允许大写字母。
var pinnedRefRe = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*:[A-Za-z0-9][A-Za-z0-9_.-]{0,127}(?:@sha256:[0-9a-f]{64})?$`)

var imageIDRe = regexp.MustCompile(`^(?:sha256:)?[0-9a-f]{64}$`)

// validatePinnedRef 校验镜像引用为显式锁定形态；拒绝 latest 与无 tag 裸仓库名
// （AGENTS.md「禁止 latest」红线与 docs/CONTAINER_OPS_DESIGN.md 第 5 节）。
func validatePinnedRef(ref string) error {
	if ref == "" {
		return errors.New("镜像引用为空")
	}
	if !pinnedRefRe.MatchString(ref) {
		return errors.New("镜像引用必须为 name:tag（可带 @sha256:digest）的锁定形态")
	}
	tag := ref
	if i := strings.LastIndex(tag, "@"); i >= 0 {
		tag = tag[:i]
	}
	tag = tag[strings.LastIndex(tag, ":")+1:]
	if strings.EqualFold(tag, "latest") {
		return errors.New("拒绝 latest 标签，必须锁定具体版本")
	}
	return nil
}

// resolveTargetImage 确定更新目标镜像。compose label com.docker.compose.image
// 可能是创建时的镜像 ID 而不是可拉取引用；ID 形态不作为更新目标，回退 Config.Image。
func resolveTargetImage(inspect *ContainerInspect) (string, error) {
	ref := ""
	if labels, ok := inspect.ConfigValue("Labels").(map[string]interface{}); ok {
		if v, ok := labels[LabelImage].(string); ok {
			ref = strings.TrimSpace(v)
		}
	}
	if ref == "" || imageIDRe.MatchString(ref) {
		ref = inspect.ConfigImage()
	}
	if err := validatePinnedRef(ref); err != nil {
		return "", fmt.Errorf("目标镜像 %q 不合法: %w", ref, err)
	}
	return ref, nil
}

// endpointKeys 重建容器时从 NetworkSettings.Networks 透传到 NetworkingConfig
// EndpointsConfig 的字段白名单（IP/MAC 等运行时分配字段不透传，由 Engine 重新分配）。
var endpointKeys = []string{"NetworkID", "Aliases", "IPAMConfig", "Links"}

// buildRecreateBody 由 inspect 结果构建 create 请求体：
// Config 全量透传（含 Env/Labels/Cmd/Healthcheck，绝不写入日志）并替换 Image；
// HostConfig 原样透传（Binds/Mounts/PortBindings/RestartPolicy/NetworkMode 等）；
// NetworkingConfig 由 NetworkSettings.Networks 白名单字段重建。
func buildRecreateBody(inspect *ContainerInspect, targetRef string) ([]byte, error) {
	var config map[string]interface{}
	if err := json.Unmarshal(inspect.Config, &config); err != nil {
		return nil, fmt.Errorf("解析容器 Config 失败: %w", err)
	}
	config["Image"] = targetRef
	// 默认主机名是旧容器短 ID，重建时丢弃让 Engine 重新派生；显式主机名保留
	if hostname, ok := config["Hostname"].(string); ok && hostname == inspect.ShortID() {
		delete(config, "Hostname")
	}
	var hostConfig json.RawMessage
	if len(inspect.HostConfig) > 0 {
		hostConfig = inspect.HostConfig
	} else {
		hostConfig = json.RawMessage(`{}`)
	}
	endpoints := map[string]interface{}{}
	for name, raw := range inspect.NetworkSettings.Networks {
		var src map[string]interface{}
		if json.Unmarshal(raw, &src) != nil {
			continue
		}
		dst := map[string]interface{}{}
		for _, k := range endpointKeys {
			if v, ok := src[k]; ok && v != nil {
				dst[k] = v
			}
		}
		endpoints[name] = dst
	}
	body := map[string]interface{}{}
	for k, v := range config {
		body[k] = v
	}
	body["HostConfig"] = hostConfig
	body["NetworkingConfig"] = map[string]interface{}{"EndpointsConfig": endpoints}
	return json.Marshal(body)
}

// executeUpdate 执行 update 任务：pull 可容忍失败（离线环境），镜像无变化则成功空转；
// 有变化时重建容器，健康等待失败回滚旧容器。
func (s *Service) executeUpdate(ctx context.Context, job *ActionJob) error {
	inspect, err := s.resolveInspect(ctx, job.Service)
	if err != nil {
		return err
	}
	targetRef, err := resolveTargetImage(inspect)
	if err != nil {
		return err
	}

	// 尝试拉取目标镜像；离线/仓库不可达可容忍（本地已有锁定镜像即可继续）
	pullOK := true
	if err := s.docker.PullImage(ctx, targetRef); err != nil {
		pullOK = false
		s.logger.Warn("镜像拉取失败，尝试使用本地镜像继续",
			"job_id", job.JobID, "service", job.Service, "image", targetRef, "error", err)
	}

	targetID, err := s.docker.ImageInspect(ctx, targetRef)
	if err != nil {
		if !pullOK && IsNotFound(err) {
			return fmt.Errorf("目标镜像 %s 本地不存在且拉取失败（离线环境请先导入镜像）", targetRef)
		}
		return fmt.Errorf("读取目标镜像 %s 信息失败: %w", targetRef, err)
	}
	if targetID == inspect.Image {
		return errUpdateNoop // 调用方按成功空转处理
	}

	origName := inspect.ObjectName()
	if origName == "" {
		return fmt.Errorf("容器名称为空，无法重建")
	}
	oldName := origName + "-old-" + job.JobID[:8]

	body, err := buildRecreateBody(inspect, targetRef)
	if err != nil {
		return err
	}

	// 停旧容器 → 改名腾出原名 → 建/起新容器 → 健康等待；失败回滚。
	// oldStarted 记录更新前运行态，回滚只恢复到原状态（原本停止的容器不被拉起）。
	oldStarted := inspect.State.Running
	if err := s.docker.StopContainer(ctx, inspect.ID, s.stopTimeoutSec); err != nil {
		return fmt.Errorf("停止旧容器失败: %w", err)
	}
	if err := s.docker.RenameContainer(ctx, inspect.ID, oldName); err != nil {
		s.rollback(ctx, inspect.ID, "", origName, &oldStarted)
		return fmt.Errorf("改名旧容器失败: %w", err)
	}
	newID, err := s.docker.CreateContainer(ctx, origName, body)
	if err != nil {
		s.rollback(ctx, inspect.ID, "", origName, &oldStarted)
		return fmt.Errorf("创建新容器失败: %w", err)
	}
	if err := s.docker.StartContainer(ctx, newID); err != nil {
		s.rollback(ctx, inspect.ID, newID, origName, &oldStarted)
		return fmt.Errorf("启动新容器失败: %w", err)
	}
	if err := s.waitHealthy(ctx, newID); err != nil {
		s.rollback(ctx, inspect.ID, newID, origName, &oldStarted)
		return fmt.Errorf("新容器健康检查未通过: %w", err)
	}
	// 新容器就绪后移除旧容器；移除失败不影响更新结果（遗留 -old- 容器可人工清理）
	if err := s.docker.RemoveContainer(ctx, inspect.ID, false); err != nil {
		s.logger.Warn("移除旧容器失败（更新已成功）",
			"job_id", job.JobID, "service", job.Service, "old_container", inspect.ShortID(), "error", err)
	}
	return nil
}

// errUpdateNoop 标记镜像无变化的成功空转（executeUpdate 内部信号）。
var errUpdateNoop = errors.New("目标镜像与当前运行镜像一致")

// rollback 尽力回滚：移除新容器 → 旧容器改回原名 → 重新拉起旧容器。
// 使用独立的 2 分钟超时上下文，避免原任务 ctx 已超时或取消时回滚全部失败。
// 各步失败只记录日志并汇总，不掩盖原始失败原因。
func (s *Service) rollback(_ context.Context, oldID, newID, origName string, oldStarted *bool) {
	rbCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var problems []string
	if newID != "" {
		if err := s.docker.StopContainer(rbCtx, newID, s.stopTimeoutSec); err != nil {
			problems = append(problems, "停止新容器: "+err.Error())
		}
		if err := s.docker.RemoveContainer(rbCtx, newID, true); err != nil {
			problems = append(problems, "移除新容器: "+err.Error())
		}
	}
	if err := s.docker.RenameContainer(rbCtx, oldID, origName); err != nil {
		problems = append(problems, "改回旧容器名: "+err.Error())
	}
	if *oldStarted {
		if err := s.docker.StartContainer(rbCtx, oldID); err != nil {
			problems = append(problems, "拉起旧容器: "+err.Error())
		}
	}
	if len(problems) > 0 {
		s.logger.Error("更新回滚存在残留步骤", "container", oldID[:minInt(12, len(oldID))], "problems", strings.Join(problems, "; "))
	} else {
		s.logger.Info("更新失败已回滚旧容器", "container", oldID[:minInt(12, len(oldID))])
	}
}

// waitHealthy 等待新容器就绪：定义了健康检查的容器等待 healthy；
// 未定义的容器要求在 settleWait 窗口内持续 Running。
func (s *Service) waitHealthy(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, s.healthTimeout)
	defer cancel()
	var runningSince time.Time
	for {
		inspect, err := s.docker.InspectContainer(ctx, id)
		if err != nil {
			return fmt.Errorf("读取新容器状态失败: %w", err)
		}
		if inspect.HasHealthcheck() {
			if inspect.State.Health.Status == "healthy" {
				return nil
			}
			if !inspect.State.Running {
				return fmt.Errorf("容器已退出（exit=%d %s）", inspect.State.ExitCode, inspect.State.Error)
			}
		} else {
			if !inspect.State.Running {
				return fmt.Errorf("容器已退出（exit=%d %s）", inspect.State.ExitCode, inspect.State.Error)
			}
			if runningSince.IsZero() {
				runningSince = time.Now()
			}
			if time.Since(runningSince) >= s.settleWait {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("等待超时（%s）", s.healthTimeout)
		case <-time.After(s.healthInterval):
		}
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
