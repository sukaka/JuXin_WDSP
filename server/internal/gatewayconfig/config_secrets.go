// config_secrets.go 整站配置版本的密钥语义：版本表不再保存密钥明文，回滚时重注入当前密钥。
//
// 背景：publisher.Rollback 直接重放历史 configuration_json 会静默恢复旧密钥
// （valkey 密码、identity_salt、扫描/文件签名/脱敏加密 key_hex、TLS 会话票据键）。
// 访问控制回滚（RollbackAccessControl 经 guardconfig.GetVersionConfig）的口径是
// 快照脱敏存储、回滚按当前设置重注入；本文件把整站配置版本统一到同一口径：
//   - saveVersion 写入 configuration_json 前经 RedactConfigSecrets 脱敏（"***" 占位）；
//   - Rollback 重放前经 reinjectConfigSecrets 按当前设置重注入，取不到则失败并明确报错；
//   - publish_smoke 属于单次发布身份，保存时整段移除，不在回滚中重放；
//   - 存量历史版本不动，含旧明文的 JSON 回滚时同样走重注入（旧值被当前值覆盖）。
package gatewayconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// redactedSecretPlaceholder 脱敏占位符（与 guardconfig.RedactGuardConfig / redactPlaceholder 一致）。
const redactedSecretPlaceholder = "***"

// walkConfigMaps 深度优先遍历 JSON 树中的所有 map 节点（含根本身）。
func walkConfigMaps(v interface{}, fn func(mapT)) {
	switch t := v.(type) {
	case mapT:
		fn(t)
		for _, child := range t {
			walkConfigMaps(child, fn)
		}
	case []interface{}:
		for _, child := range t {
			walkConfigMaps(child, fn)
		}
	}
}

// isGuardHandlerNode 判定 jiuzhang_guard 处理器节点（每应用路由的处理链元素）。
func isGuardHandlerNode(m mapT) bool { return m["handler"] == "jiuzhang_guard" }

// isACMEHTTP01HandlerNode 判定 jiuzhang_acme_http01 处理器节点（:80 ACME HTTP-01 挑战路由）。
func isACMEHTTP01HandlerNode(m mapT) bool { return m["handler"] == "jiuzhang_acme_http01" }

// isTLSTicketKeySourceNode 判定 apps.tls.session_tickets.key_source 节点
// （tls.stek.jiuzhang 静态键，generator.go 产出形态）。
func isTLSTicketKeySourceNode(m mapT) bool {
	_, hasKeys := m["keys_hex"]
	return hasKeys && m["provider"] == "jiuzhang"
}

// tlsLoadPEMRawList 提取 apps.tls.certificates.load_pem 切片（存在且非空返回 true）。
func tlsLoadPEMRawList(root mapT) ([]interface{}, bool) {
	apps, ok := root["apps"].(mapT)
	if !ok {
		return nil, false
	}
	tlsApp, ok := apps["tls"].(mapT)
	if !ok {
		return nil, false
	}
	certs, ok := tlsApp["certificates"].(mapT)
	if !ok {
		return nil, false
	}
	rawList, ok := certs["load_pem"].([]interface{})
	if !ok || len(rawList) == 0 {
		return nil, false
	}
	return rawList, true
}

// parseConfigJSON 解析配置 JSON 为可遍历 map。
func parseConfigJSON(configJSON string) (mapT, error) {
	var root mapT
	if err := json.Unmarshal([]byte(configJSON), &root); err != nil {
		return nil, fmt.Errorf("parse config json: %w", err)
	}
	return root, nil
}

// redactMapSecret 将 map 中非空字符串字段替换为脱敏占位符。
func redactMapSecret(m mapT, key string) {
	if s, ok := m[key].(string); ok && s != "" {
		m[key] = redactedSecretPlaceholder
	}
}

// RedactConfigSecrets 脱敏配置 JSON 中的密钥类字段（版本表存储与预览用）：
// guard 段（valkey.password、identity_salt、api_scan_verification.key_hex、
// api_file_signature.key_hex、api_mask_crypto.key_hex、api_authz_object_hmac_key_hex、
// bot_policy.signing_keys）、TLS 会话票据 keys_hex 以及 apps.tls.certificates.load_pem[*].key
// 均以 "***" 占位；publish_smoke 整段移除；certificate、tags、地址、kid 等非密钥字段原样保留。
func RedactConfigSecrets(configJSON string) (string, error) {
	root, err := parseConfigJSON(configJSON)
	if err != nil {
		return "", err
	}
	walkConfigMaps(root, func(m mapT) {
		if isGuardHandlerNode(m) {
			// 探针密钥只对本次发布有效；删除整段可避免旧发布身份被快照或回滚重放。
			delete(m, "publish_smoke")
			redactMapSecret(m, "identity_salt")
			redactMapSecret(m, "api_authz_object_hmac_key_hex")
			if v, ok := m["api_authz_previous_valid"].(mapT); ok {
				redactMapSecret(v, "object_hmac_key_hex")
			}
			if v, ok := m["valkey"].(mapT); ok {
				redactMapSecret(v, "password")
			}
			if v, ok := m["api_scan_verification"].(mapT); ok {
				redactMapSecret(v, "key_hex")
			}
			if v, ok := m["api_file_signature"].(mapT); ok {
				redactMapSecret(v, "key_hex")
			}
			if v, ok := m["api_mask_crypto"].(mapT); ok {
				redactMapSecret(v, "key_hex")
			}
			if bp, ok := m["bot_policy"].(mapT); ok {
				if sk, ok := bp["signing_keys"].(mapT); ok {
					for k, val := range sk {
						if s, ok := val.(string); ok && s != "" {
							sk[k] = redactedSecretPlaceholder
						}
					}
				}
			}
		}
		if isACMEHTTP01HandlerNode(m) {
			if v, ok := m["valkey"].(mapT); ok {
				redactMapSecret(v, "password")
			}
		}
		if isTLSTicketKeySourceNode(m) {
			if keys, ok := m["keys_hex"].([]interface{}); ok {
				for i, k := range keys {
					if s, ok := k.(string); ok && s != "" {
						keys[i] = redactedSecretPlaceholder
					}
				}
			}
		}
	})
	if rawList, ok := tlsLoadPEMRawList(root); ok {
		for _, item := range rawList {
			if entry, ok := item.(mapT); ok {
				redactMapSecret(entry, "key")
			}
		}
	}
	out, err := marshalDeterministic(root)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// configSecretNeeds 记录历史配置中出现的密钥类字段（决定回滚需从当前设置取哪些值）。
type configSecretNeeds struct {
	valkey         bool
	identitySalt   bool
	scanVerify     bool
	fileSignature  bool
	maskCrypto     bool
	authzObjectKey bool
	tlsTicketKey   bool
	botSigningKeys bool
}

func (n *configSecretNeeds) any() bool {
	return n.valkey || n.identitySalt || n.scanVerify || n.fileSignature || n.maskCrypto || n.authzObjectKey || n.tlsTicketKey || n.botSigningKeys
}

// reinjectConfigSecrets 回滚重放前将历史配置 JSON 中 guard 段密钥类字段替换为当前设置值
// （与 RollbackAccessControl 经 GetVersionConfig 重注入同口径；新版本快照为脱敏占位、
// 存量历史版本可能为旧明文，统一按字段存在性重注入，不信任快照内的密钥值）。
// 历史配置含密钥字段而当前设置取不到值时如实报错（回滚失败），不回放占位符或旧明文；
// 配置不含密钥字段时原样返回（字节不变、不触发当前配置读取，纯 WAF 形态零行为变化）。
func (p *Publisher) reinjectConfigSecrets(ctx context.Context, configJSON string) (string, error) {
	root, err := parseConfigJSON(configJSON)
	if err != nil {
		return "", fmt.Errorf("回滚配置 JSON 解析失败: %w", err)
	}
	var needs configSecretNeeds
	walkConfigMaps(root, func(m mapT) {
		if isGuardHandlerNode(m) {
			if _, ok := m["valkey"]; ok {
				needs.valkey = true
			}
			if _, ok := m["identity_salt"]; ok {
				needs.identitySalt = true
			}
			if _, ok := m["api_scan_verification"]; ok {
				needs.scanVerify = true
			}
			if _, ok := m["api_file_signature"]; ok {
				needs.fileSignature = true
			}
			if _, ok := m["api_mask_crypto"]; ok {
				needs.maskCrypto = true
			}
			if _, ok := m["api_authz_object_hmac_key_hex"]; ok {
				needs.authzObjectKey = true
			}
			if v, ok := m["api_authz_previous_valid"].(mapT); ok {
				if _, exists := v["object_hmac_key_hex"]; exists {
					needs.authzObjectKey = true
				}
			}
			if bp, ok := m["bot_policy"].(mapT); ok {
				if sk, ok := bp["signing_keys"].(mapT); ok && len(sk) > 0 {
					needs.botSigningKeys = true
				}
			}
		}
		if isACMEHTTP01HandlerNode(m) {
			if _, ok := m["valkey"]; ok {
				needs.valkey = true
			}
		}
		if isTLSTicketKeySourceNode(m) {
			needs.tlsTicketKey = true
		}
	})
	loadPEMList, hasLoadPEM := tlsLoadPEMRawList(root)
	if !needs.any() && !hasLoadPEM {
		return configJSON, nil
	}
	if needs.any() {
		if p.guard == nil {
			return "", fmt.Errorf("回滚配置包含 guard 密钥字段，但未装配访问控制配置提供者，无法重注入当前密钥")
		}
		cur, err := p.guard.BuildGuardConfig(ctx)
		if err != nil {
			return "", fmt.Errorf("回滚重注入当前密钥：读取当前访问控制配置失败: %w", err)
		}
		ticketKeys := cur.EffectiveTLSSessionTicketKeys()
		// 当前取值齐备性校验：取不到即失败并明确报错，不静默回放占位符或旧明文
		if needs.valkey && cur.Valkey == nil {
			return "", fmt.Errorf("回滚重注入当前密钥失败：历史配置含 valkey 段，但当前未配置 Valkey 连接")
		}
		if needs.identitySalt && cur.IdentitySalt == "" {
			return "", fmt.Errorf("回滚重注入当前密钥失败：历史配置含 identity_salt，但当前 gateway_runtime 设置未配置该键")
		}
		if needs.scanVerify && (cur.APIScanVerification == nil || cur.APIScanVerification.KeyHex == "") {
			return "", fmt.Errorf("回滚重注入当前密钥失败：历史配置含 api_scan_verification，但当前未配置扫描签名密钥")
		}
		if needs.fileSignature && (cur.APIFileSignature == nil || cur.APIFileSignature.KeyHex == "") {
			return "", fmt.Errorf("回滚重注入当前密钥失败：历史配置含 api_file_signature，但当前未配置文件签名密钥")
		}
		if needs.maskCrypto && (cur.APIMaskCrypto == nil || cur.APIMaskCrypto.KeyHex == "") {
			return "", fmt.Errorf("回滚重注入当前密钥失败：历史配置含 api_mask_crypto，但当前未配置脱敏加密密钥")
		}
		if needs.authzObjectKey && cur.APIAuthzObjectHMACKeyHex == "" {
			return "", fmt.Errorf("回滚重注入当前密钥失败：历史配置含 api_authz_object_hmac_key_hex，但当前未配置对象引用 HMAC 密钥")
		}
		if needs.tlsTicketKey && len(ticketKeys) == 0 {
			return "", fmt.Errorf("回滚重注入当前密钥失败：历史配置含 TLS 会话票据键，但当前 gateway_runtime 设置未配置 tls_session_ticket_key")
		}
		if needs.botSigningKeys && len(cur.BotSigningKeys) == 0 {
			return "", fmt.Errorf("回滚重注入当前密钥失败：历史配置含 bot_policy.signing_keys，但当前未配置 Bot 签名密钥")
		}
		// 重注入：valkey 段整体按当前运行时替换（地址/凭据/库同口径，与 InjectRuntimeSecrets 一致）；
		// 其余密钥字段替换为当前设置值
		walkConfigMaps(root, func(m mapT) {
			if isGuardHandlerNode(m) {
				if _, ok := m["valkey"]; ok {
					m["valkey"] = cur.Valkey
				}
				if _, ok := m["identity_salt"]; ok {
					m["identity_salt"] = cur.IdentitySalt
				}
				if _, ok := m["api_scan_verification"]; ok {
					m["api_scan_verification"] = cur.APIScanVerification
				}
				if _, ok := m["api_file_signature"]; ok {
					m["api_file_signature"] = cur.APIFileSignature
				}
				if _, ok := m["api_mask_crypto"]; ok {
					m["api_mask_crypto"] = cur.APIMaskCrypto
				}
				if _, ok := m["api_authz_object_hmac_key_hex"]; ok {
					m["api_authz_object_hmac_key_hex"] = cur.APIAuthzObjectHMACKeyHex
				}
				if v, ok := m["api_authz_previous_valid"].(mapT); ok {
					if _, exists := v["object_hmac_key_hex"]; exists {
						v["object_hmac_key_hex"] = cur.APIAuthzObjectHMACKeyHex
					}
				}
				if bp, ok := m["bot_policy"].(mapT); ok {
					if sk, ok := bp["signing_keys"].(mapT); ok && len(sk) > 0 {
						bp["signing_keys"] = cur.BotSigningKeys
					}
				}
			}
			if isACMEHTTP01HandlerNode(m) {
				if _, ok := m["valkey"]; ok {
					m["valkey"] = cur.Valkey
				}
			}
			if isTLSTicketKeySourceNode(m) {
				m["keys_hex"] = ticketKeys
			}
		})
	}
	if hasLoadPEM {
		if err := p.reinjectLoadPEMPrivateKeys(ctx, loadPEMList); err != nil {
			return "", err
		}
	}
	out, err := marshalDeterministic(root)
	if err != nil {
		return "", fmt.Errorf("回滚配置重序列化失败: %w", err)
	}
	return string(out), nil
}

// reinjectLoadPEMPrivateKeys 按 load_pem[*].tags[0]（证书 UUID）从证书仓储解密回填当前私钥 PEM；
// 任一条目缺少有效标签、非 UUID、证书已删除或私钥解密失败均 fail-closed 显式报错，绝不回放 "***"。
func (p *Publisher) reinjectLoadPEMPrivateKeys(ctx context.Context, loadPEMList []interface{}) error {
	loadKey := p.certKeyLoader
	if loadKey == nil && p.certs != nil {
		loadKey = p.certs.GetDecryptedKey
	}
	if loadKey == nil {
		return fmt.Errorf("回滚重注入证书私钥失败：配置包含 TLS 内联证书（load_pem），但未装配证书仓储，无法解密私钥")
	}
	cache := make(map[uuid.UUID]string, len(loadPEMList))
	for i, raw := range loadPEMList {
		entry, ok := raw.(mapT)
		if !ok {
			return fmt.Errorf("回滚重注入证书私钥失败：load_pem[%d] 格式非法", i)
		}
		tags, ok := entry["tags"].([]interface{})
		if !ok || len(tags) == 0 {
			return fmt.Errorf("回滚重注入证书私钥失败：load_pem[%d] 缺少证书标识 tags，无法定位私钥", i)
		}
		tagStr, ok := tags[0].(string)
		tagStr = strings.TrimSpace(tagStr)
		if !ok || tagStr == "" {
			return fmt.Errorf("回滚重注入证书私钥失败：load_pem[%d] 证书标识为空", i)
		}
		certID, err := uuid.Parse(tagStr)
		if err != nil {
			return fmt.Errorf("回滚重注入证书私钥失败：load_pem[%d] 证书标识 %q 不是合法 UUID: %w", i, tagStr, err)
		}
		keyPEM, cached := cache[certID]
		if !cached {
			keyPEM, err = loadKey(ctx, certID)
			if err != nil {
				return fmt.Errorf("回滚重注入证书私钥失败：证书 %s 读取或解密私钥失败（证书可能已删除或主密钥不可用）: %w", certID, err)
			}
			trimmed := strings.TrimSpace(keyPEM)
			if trimmed == "" || trimmed == redactedSecretPlaceholder {
				return fmt.Errorf("回滚重注入证书私钥失败：证书 %s 解密结果为空或仍为脱敏占位", certID)
			}
			cache[certID] = keyPEM
		}
		entry["key"] = keyPEM
	}
	return nil
}
