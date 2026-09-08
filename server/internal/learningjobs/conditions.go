// conditions.go 学习生成多条件（P0-01 加深，迁移 000038 配置键）：
// 从 system_settings 组 api_learning 读取字符串数值（带默认与校验，非法值回落默认并告警），
// 纯函数判定 RUNNING 任务是否达标——全部条件满足才达标；超期未达标由 janitor 置 FAILED。
//
// 条件一览（键名 → 语义）：
//   - min_valid_samples               有效样本数全局下限，与每任务 sample_target 取较大者；
//   - min_unique_ips                  accepted 样本去重来源 IP 数下限（0=不要求）；
//   - min_unique_identities           accepted 样本去重身份数下限（0=不要求）；
//   - min_learning_duration_seconds   最短学习时长（0=不要求；起点=首次落样或任务启动）；
//   - max_learning_duration_seconds   最长学习时限（超期未达标 → FAILED+last_error）；
//   - minimum_success_ratio           accepted 样本 2xx/3xx 成功率下限（0=不要求；
//     无响应状态码的样本不计入分母）。
package learningjobs

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/jiuzhang-waf/server/internal/apiassets"
)

// 配置键（system_settings 组 api_learning）。
const (
	keyMinValidSamples = "min_valid_samples"
	keyMinUniqueIPs    = "min_unique_ips"
	keyMinUniqueIDs    = "min_unique_identities"
	keyMinDurationSec  = "min_learning_duration_seconds"
	keyMaxDurationSec  = "max_learning_duration_seconds"
	keyMinSuccessRatio = "minimum_success_ratio"
)

// LearningConditions 学习生成条件（全部满足才达标）。
type LearningConditions struct {
	MinValidSamples     int           // 有效样本数全局下限
	MinUniqueIPs        int           // 去重来源 IP 下限（0=不要求）
	MinUniqueIdentities int           // 去重身份下限（0=不要求）
	MinDuration         time.Duration // 最短学习时长（0=不要求）
	MaxDuration         time.Duration // 最长学习时限（0=不超期；默认 7 天）
	MinSuccessRatio     float64       // 2xx/3xx 成功率下限（0=不要求，合法区间 [0,1]）
}

// 默认条件（与迁移 000038 种子一致；缺省不改变既有「仅 sample_target」行为）与合法区间。
const (
	defMinValidSamples = 10     // = apiassets.MinSampleTarget：全局下限默认不抬升任何合法目标
	defMinUniqueIPs    = 1      // 至少一个可识别来源（来源指纹为空的学习无防投毒意义）
	defMinUniqueIDs    = 0      // 身份指纹常缺失，默认不要求
	defMinDurationSec  = 0      // 默认不要求最短时长
	defMaxDurationSec  = 604800 // 默认 7 天：长期不达标任务置 FAILED 而非无限挂起
	defMinSuccessRatio = 0.0    // 默认不要求成功率

	maxValidSamples   = 1000000
	maxUniqueCount    = 1000000
	maxDurationSecCap = 86400 * 365
	minMaxDurationSec = 60
)

// DefaultLearningConditions 默认条件（未注入设置或读取失败时使用）。
func DefaultLearningConditions() LearningConditions {
	return LearningConditions{
		MinValidSamples:     defMinValidSamples,
		MinUniqueIPs:        defMinUniqueIPs,
		MinUniqueIdentities: defMinUniqueIDs,
		MinDuration:         defMinDurationSec * time.Second,
		MaxDuration:         defMaxDurationSec * time.Second,
		MinSuccessRatio:     defMinSuccessRatio,
	}
}

// LoadLearningConditions 从设置加载条件（字符串数值解析 + 区间校验；非法值回落默认并告警，
// 不静默沿用错误配置也不阻断调度）。settings 为 nil 时全默认。
func LoadLearningConditions(ctx context.Context, settings SettingsProvider) LearningConditions {
	c := DefaultLearningConditions()
	if settings == nil {
		return c
	}
	c.MinValidSamples = parseIntSetting(ctx, settings, keyMinValidSamples, defMinValidSamples, 1, maxValidSamples)
	c.MinUniqueIPs = parseIntSetting(ctx, settings, keyMinUniqueIPs, defMinUniqueIPs, 0, maxUniqueCount)
	c.MinUniqueIdentities = parseIntSetting(ctx, settings, keyMinUniqueIDs, defMinUniqueIDs, 0, maxUniqueCount)
	c.MinDuration = time.Duration(parseIntSetting(ctx, settings, keyMinDurationSec, defMinDurationSec, 0, maxDurationSecCap)) * time.Second
	c.MaxDuration = time.Duration(parseIntSetting(ctx, settings, keyMaxDurationSec, defMaxDurationSec, minMaxDurationSec, maxDurationSecCap)) * time.Second
	c.MinSuccessRatio = parseRatioSetting(ctx, settings, keyMinSuccessRatio, defMinSuccessRatio)
	return c
}

// parseIntSetting 读取字符串数值设置：解析失败或越界回落默认（告警留痕）。
func parseIntSetting(ctx context.Context, settings SettingsProvider, key string, def, min, max int) int {
	raw := settings.GetString(ctx, "api_learning", key, strconv.Itoa(def))
	n, err := strconv.Atoi(raw)
	if err != nil || n < min || n > max {
		slog.Warn("invalid api_learning setting, fallback to default",
			"key", key, "value", raw, "default", def)
		return def
	}
	return n
}

// parseRatioSetting 读取成功率设置（[0,1] 浮点；非法回落默认）。
func parseRatioSetting(ctx context.Context, settings SettingsProvider, key string, def float64) float64 {
	raw := settings.GetString(ctx, "api_learning", key, strconv.FormatFloat(def, 'f', -1, 64))
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil || f < 0 || f > 1 {
		slog.Warn("invalid api_learning setting, fallback to default",
			"key", key, "value", raw, "default", def)
		return def
	}
	return f
}

// EvaluateLearningConditions 多条件判定（纯函数，便于单测）：返回未满足原因列表，空=达标。
// 每条原因带当前值/要求值，直接用于超期 FAILED 的 last_error 说明。
func EvaluateLearningConditions(j *apiassets.LearningJobProgress, c LearningConditions, now time.Time) []string {
	var unmet []string
	// 1. 有效样本数：每任务目标与全局下限同时满足（sample_target=0 的历史任务恒不达标，不空转）。
	effTarget := max(j.SampleTarget, c.MinValidSamples)
	if !j.ThresholdReached() || j.ValidCount < effTarget {
		unmet = append(unmet, fmt.Sprintf("有效样本数不足（%d/%d）", j.ValidCount, effTarget))
	}
	// 2. 来源 IP 多样性（0=不要求）。
	if c.MinUniqueIPs > 0 && j.UniqueIPs < c.MinUniqueIPs {
		unmet = append(unmet, fmt.Sprintf("去重来源 IP 不足（%d/%d）", j.UniqueIPs, c.MinUniqueIPs))
	}
	// 3. 身份多样性（0=不要求）。
	if c.MinUniqueIdentities > 0 && j.UniqueIdentities < c.MinUniqueIdentities {
		unmet = append(unmet, fmt.Sprintf("去重身份不足（%d/%d）", j.UniqueIdentities, c.MinUniqueIdentities))
	}
	// 4. 最短学习时长（0=不要求；起点=首次落样，无落样回退任务启动时间）。
	if c.MinDuration > 0 && now.Sub(j.LearningStartAt()) < c.MinDuration {
		unmet = append(unmet, fmt.Sprintf("学习时长不足（%s/%s）",
			now.Sub(j.LearningStartAt()).Round(time.Second), c.MinDuration))
	}
	// 5. 成功率（0=不要求；分母=带状态码的 accepted 样本，无分母视为无证据不达标）。
	if c.MinSuccessRatio > 0 {
		if j.StatusSampleCount == 0 {
			unmet = append(unmet, "成功率无判定原料（无带状态码的 accepted 样本）")
		} else if ratio := float64(j.SuccessCount) / float64(j.StatusSampleCount); ratio < c.MinSuccessRatio {
			unmet = append(unmet, fmt.Sprintf("成功率不足（%d/%d=%.2f/%.2f）",
				j.SuccessCount, j.StatusSampleCount, ratio, c.MinSuccessRatio))
		}
	}
	return unmet
}

// LearningExpired 超期判定：距学习起点超过最长时限（MaxDuration>0 才生效）。
func LearningExpired(j *apiassets.LearningJobProgress, c LearningConditions, now time.Time) bool {
	return c.MaxDuration > 0 && now.Sub(j.LearningStartAt()) > c.MaxDuration
}
