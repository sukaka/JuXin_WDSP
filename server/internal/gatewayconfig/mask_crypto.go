package gatewayconfig

// GuardMaskCrypto ENCRYPT/MAP 运行时密钥；key_hex 不进入版本快照或日志。
type GuardMaskCrypto struct {
	KID    string `json:"kid"`
	KeyHex string `json:"key_hex"`
}
