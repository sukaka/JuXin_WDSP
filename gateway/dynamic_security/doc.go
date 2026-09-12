// Package dynamic_security 统一动态安全引擎根包锚点。
// 引擎实现位于 context/parser/normalizer/classifier/detectors/decision/events/learning/pipeline 等子包；
// 根包存在的原因是 xcaddy --with 的本地路径替换要求被替换模块含可导入的 Go 包（无副作用空包）。
package dynamic_security
