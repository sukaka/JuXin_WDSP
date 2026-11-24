//go:build linux

package selfmon

// NewDefaultSampler 返回 Linux 默认采样器（/proc/self/stat + /proc/self/status VmRSS）。
func NewDefaultSampler() Sampler {
	return NewProcSampler()
}
