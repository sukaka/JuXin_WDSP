package gatewayconfig

// GuardRiskPolicyOverride 是按应用下发的风险策略覆盖；缺省不下发并继承全局策略。
type GuardRiskPolicyOverride struct {
	ApplicationID string          `json:"application_id"`
	Policy        GuardRiskPolicy `json:"policy"`
	// SharedDeviceAccountLimit 同设备可信账号观察阈值；0=默认3，仅影响 OBSERVE 信号。
	SharedDeviceAccountLimit int `json:"shared_device_account_limit,omitempty"`
}
