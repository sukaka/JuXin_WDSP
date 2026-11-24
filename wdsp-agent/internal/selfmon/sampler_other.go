//go:build !linux && !darwin && !windows

package selfmon

// NewDefaultSampler 其他平台回退至 ProcSampler（读取失败由上层跳过）。
func NewDefaultSampler() Sampler {
	return NewProcSampler()
}
