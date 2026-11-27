-- 000251 自定义拦截页面与多版本管理：
--   a) block_pages：拦截页模板主表（支持可视化配置 VISUAL 与自定义 HTML/CSS 源码 HTML 双模式，带乐观锁版本号）
--   b) block_page_versions：不可变修订版本历史（每次创建/更新/回滚追加新版本，含净化后 rendered_html 快照，支持历史版本查看、回滚与绑定锁定）
--   c) block_page_bindings：生效绑定表（全局默认 / 应用级覆盖 × 拦截场景 DEFAULT/WAF/ACCESS_CONTROL/RATE_LIMIT，可选锁定历史版本或跟随最新版）
--   d) 种子化 4 套内置预设模板（v1）及权限点 block_pages.read / block_pages.manage（遵循 000232 三权边界，不默认写入生效绑定以保持存量零行为变化）
BEGIN;

-- a) 拦截页模板主表
CREATE TABLE IF NOT EXISTS block_pages (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    name          VARCHAR(128) NOT NULL UNIQUE,
    description   TEXT         NOT NULL DEFAULT '',
    editor_mode   VARCHAR(16)  NOT NULL DEFAULT 'VISUAL'
                  CHECK (editor_mode IN ('VISUAL', 'HTML')),
    theme         VARCHAR(32)  NOT NULL DEFAULT 'classic_dark'
                  CHECK (theme IN ('classic_dark', 'clean_light', 'enterprise_blue', 'alert_red', 'amber_limit')),
    visual_config JSONB        NOT NULL DEFAULT '{}'::jsonb,
    html_content  TEXT         NOT NULL DEFAULT '',
    rendered_html TEXT         NOT NULL DEFAULT '',
    status_code   INT          NOT NULL DEFAULT 0
                  CHECK (status_code = 0 OR (status_code >= 400 AND status_code <= 599)),
    json_code     VARCHAR(128) NOT NULL DEFAULT '',
    json_message  VARCHAR(512) NOT NULL DEFAULT '',
    version       INT          NOT NULL DEFAULT 1 CHECK (version >= 1),
    is_builtin    BOOLEAN      NOT NULL DEFAULT FALSE,
    created_by    VARCHAR(128) NOT NULL DEFAULT '',
    updated_by    VARCHAR(128) NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

COMMENT ON TABLE block_pages IS
    '自定义拦截页面模板主表（支持 VISUAL 可视化与 HTML 源码双模式、多套模板与乐观锁版本递增）';

CREATE INDEX IF NOT EXISTS idx_block_pages_updated_at
    ON block_pages (updated_at DESC, name ASC);

-- b) 不可变修订版本历史表
CREATE TABLE IF NOT EXISTS block_page_versions (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    block_page_id UUID         NOT NULL REFERENCES block_pages(id) ON DELETE CASCADE,
    version       INT          NOT NULL CHECK (version >= 1),
    editor_mode   VARCHAR(16)  NOT NULL CHECK (editor_mode IN ('VISUAL', 'HTML')),
    theme         VARCHAR(32)  NOT NULL DEFAULT 'classic_dark'
                  CHECK (theme IN ('classic_dark', 'clean_light', 'enterprise_blue', 'alert_red', 'amber_limit')),
    visual_config JSONB        NOT NULL DEFAULT '{}'::jsonb,
    html_content  TEXT         NOT NULL DEFAULT '',
    rendered_html TEXT         NOT NULL DEFAULT '',
    status_code   INT          NOT NULL DEFAULT 0
                  CHECK (status_code = 0 OR (status_code >= 400 AND status_code <= 599)),
    json_code     VARCHAR(128) NOT NULL DEFAULT '',
    json_message  VARCHAR(512) NOT NULL DEFAULT '',
    change_note   TEXT         NOT NULL DEFAULT '',
    created_by    VARCHAR(128) NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (block_page_id, version)
);

COMMENT ON TABLE block_page_versions IS
    '自定义拦截页面不可变修订版本历史（每次创建/编辑/回滚追加新版本，支持回滚与绑定锁定指定历史版本）';

CREATE INDEX IF NOT EXISTS idx_block_page_versions_page_ver
    ON block_page_versions (block_page_id, version DESC);

-- c) 生效绑定表（全局默认 + 应用级覆盖 × 拦截场景）
CREATE TABLE IF NOT EXISTS block_page_bindings (
    id             UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID         NULL REFERENCES applications(id) ON DELETE CASCADE,
    scene          VARCHAR(32)  NOT NULL DEFAULT 'DEFAULT'
                   CHECK (scene IN ('DEFAULT', 'WAF', 'ACCESS_CONTROL', 'RATE_LIMIT')),
    block_page_id  UUID         NOT NULL REFERENCES block_pages(id) ON DELETE RESTRICT,
    pinned_version INT          NULL CHECK (pinned_version IS NULL OR pinned_version >= 1),
    enabled        BOOLEAN      NOT NULL DEFAULT TRUE,
    updated_by     VARCHAR(128) NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);

COMMENT ON TABLE block_page_bindings IS
    '自定义拦截页生效绑定（全局或指定应用按拦截场景 DEFAULT/WAF/ACCESS_CONTROL/RATE_LIMIT 绑定模板与版本）';

CREATE UNIQUE INDEX IF NOT EXISTS uq_block_page_bindings_scope_scene
    ON block_page_bindings (COALESCE(application_id, '00000000-0000-0000-0000-000000000000'::uuid), scene);

CREATE INDEX IF NOT EXISTS idx_block_page_bindings_page
    ON block_page_bindings (block_page_id);

-- d) 种子化 4 套内置预设模板（仅提供开箱即用的多风格样板，不自动启用绑定，确保升级后存量行为逐字节兼容）
INSERT INTO block_pages (
    id, name, description, editor_mode, theme, visual_config, html_content, rendered_html,
    status_code, json_code, json_message, version, is_builtin, created_by, updated_by
) VALUES
(
    '11111111-2222-4333-8444-555555550001',
    '经典暗色安全拦截页',
    '深空蓝暗色安全防护样式，适合默认 403/WAF 安全拦截展示',
    'VISUAL',
    'classic_dark',
    '{"badge":"安全拦截","title":"请求已被安全策略阻断","subtitle":"Security Policy Enforcement","description":"您发起的请求触发了本站的安全防护策略，已被拦截。如果您认为这是误判，请记录下方信息并联系系统管理员处理。","contact_info":"请联系您的系统管理员，并提供请求编号与发生时间，以便快速定位和处理。","brand_name":"九章WEB应用智能防护系统","show_request_id":true,"show_timestamp":true,"show_client_ip":true,"show_domain":true,"show_status_code":true}'::jsonb,
    '',
    '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>请求已被安全策略阻断</title><style>*{margin:0;padding:0;box-sizing:border-box;}body{font-family:"PingFang SC","Microsoft YaHei","Helvetica Neue",Arial,sans-serif;background:#1b2431;color:#e6e9ef;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;}.bp-card{max-width:580px;width:100%;background:#232f42;border:1px solid #33415c;border-radius:10px;padding:40px 36px;box-shadow:0 12px 36px rgba(0,0,0,0.35);}.bp-badge{display:inline-block;background:rgba(224,108,117,0.16);color:#e06c75;border:1px solid rgba(224,108,117,0.42);border-radius:4px;font-size:13px;padding:4px 12px;margin-bottom:18px;letter-spacing:1px;}h1{font-size:22px;font-weight:600;margin-bottom:8px;color:#f0f3f8;}.bp-sub{font-size:13px;color:#7c8aa5;margin-bottom:14px;}.bp-desc{font-size:14px;line-height:1.8;color:#9aa7bd;margin-bottom:24px;}.bp-meta{background:#1b2431;border:1px solid #2c3a52;border-radius:6px;padding:14px 18px;font-size:13px;margin-bottom:22px;}.bp-row{display:flex;justify-content:space-between;gap:16px;padding:5px 0;word-break:break-all;}.bp-label{color:#7c8aa5;flex-shrink:0;}.bp-val{color:#c3cede;font-family:"SF Mono",Menlo,Consolas,monospace;text-align:right;}.bp-contact{font-size:13px;color:#8fa0bb;line-height:1.7;border-top:1px solid #2c3a52;padding-top:16px;}.bp-brand{margin-top:22px;font-size:12px;color:#5a6a86;text-align:center;letter-spacing:2px;}</style></head><body><div class="bp-card"><div class="bp-badge">安全拦截</div><h1>请求已被安全策略阻断</h1><div class="bp-sub">Security Policy Enforcement</div><p class="bp-desc">您发起的请求触发了本站的安全防护策略，已被拦截。如果您认为这是误判，请记录下方信息并联系系统管理员处理。</p><div class="bp-meta"><div class="bp-row"><span class="bp-label">请求编号</span><span class="bp-val">{{request_id}}</span></div><div class="bp-row"><span class="bp-label">发生时间</span><span class="bp-val">{{time}}</span></div><div class="bp-row"><span class="bp-label">客户端 IP</span><span class="bp-val">{{client_ip}}</span></div><div class="bp-row"><span class="bp-label">访问站点</span><span class="bp-val">{{domain}}</span></div><div class="bp-row"><span class="bp-label">状态码</span><span class="bp-val">{{status_code}}</span></div></div><p class="bp-contact">请联系您的系统管理员，并提供请求编号与发生时间，以便快速定位和处理。</p><div class="bp-brand">九章WEB应用智能防护系统</div></div></body></html>',
    0,
    '',
    '',
    1,
    TRUE,
    'system',
    'system'
),
(
    '11111111-2222-4333-8444-555555550002',
    '简约企业浅色拦截页',
    '现代明净浅色卡片风格，适合面向外部客户与企业官网的品牌化安全提示',
    'VISUAL',
    'clean_light',
    '{"badge":"访问受限","title":"您的请求未能通过安全校验","subtitle":"Access Restricted","description":"当前请求触发了站点安全保护机制，暂无法继续访问。如为正常业务操作，请将下方事件编号反馈给技术支持团队。","contact_info":"如需协助，请联系网站技术支持并提供下方请求编号。","brand_name":"企业安全防护中心","show_request_id":true,"show_timestamp":true,"show_client_ip":true,"show_domain":true,"show_status_code":true}'::jsonb,
    '',
    '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>您的请求未能通过安全校验</title><style>*{margin:0;padding:0;box-sizing:border-box;}body{font-family:"PingFang SC","Microsoft YaHei","Helvetica Neue",Arial,sans-serif;background:#f3f5f9;color:#1f2937;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;}.bp-card{max-width:580px;width:100%;background:#ffffff;border:1px solid #e5e7eb;border-radius:12px;padding:40px 36px;box-shadow:0 10px 30px rgba(15,23,42,0.08);}.bp-badge{display:inline-block;background:#eff6ff;color:#1d4ed8;border:1px solid #bfdbfe;border-radius:999px;font-size:12px;font-weight:600;padding:4px 12px;margin-bottom:18px;}h1{font-size:22px;font-weight:600;margin-bottom:8px;color:#111827;}.bp-sub{font-size:13px;color:#6b7280;margin-bottom:14px;}.bp-desc{font-size:14px;line-height:1.8;color:#4b5563;margin-bottom:24px;}.bp-meta{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:14px 18px;font-size:13px;margin-bottom:22px;}.bp-row{display:flex;justify-content:space-between;gap:16px;padding:5px 0;word-break:break-all;}.bp-label{color:#64748b;flex-shrink:0;}.bp-val{color:#0f172a;font-family:"SF Mono",Menlo,Consolas,monospace;text-align:right;}.bp-contact{font-size:13px;color:#64748b;line-height:1.7;border-top:1px solid #e5e7eb;padding-top:16px;}.bp-brand{margin-top:22px;font-size:12px;color:#94a3b8;text-align:center;letter-spacing:1px;}</style></head><body><div class="bp-card"><div class="bp-badge">访问受限</div><h1>您的请求未能通过安全校验</h1><div class="bp-sub">Access Restricted</div><p class="bp-desc">当前请求触发了站点安全保护机制，暂无法继续访问。如为正常业务操作，请将下方事件编号反馈给技术支持团队。</p><div class="bp-meta"><div class="bp-row"><span class="bp-label">请求编号</span><span class="bp-val">{{request_id}}</span></div><div class="bp-row"><span class="bp-label">发生时间</span><span class="bp-val">{{time}}</span></div><div class="bp-row"><span class="bp-label">客户端 IP</span><span class="bp-val">{{client_ip}}</span></div><div class="bp-row"><span class="bp-label">访问站点</span><span class="bp-val">{{domain}}</span></div><div class="bp-row"><span class="bp-label">状态码</span><span class="bp-val">{{status_code}}</span></div></div><p class="bp-contact">如需协助，请联系网站技术支持并提供下方请求编号。</p><div class="bp-brand">企业安全防护中心</div></div></body></html>',
    0,
    '',
    '',
    1,
    TRUE,
    'system',
    'system'
),
(
    '11111111-2222-4333-8444-555555550003',
    '高危攻击警示拦截页',
    '强对比红黑警示风格，适合 WAF 高危攻击与严格访问控制封禁场景',
    'VISUAL',
    'alert_red',
    '{"badge":"高危安全拦截","title":"检测到异常攻击行为，访问已拒绝","subtitle":"Malicious Request Blocked","description":"安全防护网关检测到当前请求存在潜在恶意载荷或违规访问特征，已立即阻断并记录安全审计日志。","contact_info":"若您确认本次操作合规，请保存请求编号联系安全运营团队核查。","brand_name":"九章动态安全防护网关","show_request_id":true,"show_timestamp":true,"show_client_ip":true,"show_domain":true,"show_status_code":true}'::jsonb,
    '',
    '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>检测到异常攻击行为，访问已拒绝</title><style>*{margin:0;padding:0;box-sizing:border-box;}body{font-family:"PingFang SC","Microsoft YaHei","Helvetica Neue",Arial,sans-serif;background:#181216;color:#f5e9ec;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;}.bp-card{max-width:580px;width:100%;background:#241a20;border:1px solid #5c2832;border-top:4px solid #dc2626;border-radius:10px;padding:38px 36px;box-shadow:0 14px 40px rgba(0,0,0,0.45);}.bp-badge{display:inline-block;background:rgba(220,38,38,0.18);color:#f87171;border:1px solid rgba(248,113,113,0.45);border-radius:4px;font-size:13px;font-weight:600;padding:4px 12px;margin-bottom:18px;}h1{font-size:22px;font-weight:600;margin-bottom:8px;color:#fff1f2;}.bp-sub{font-size:13px;color:#fda4af;margin-bottom:14px;}.bp-desc{font-size:14px;line-height:1.8;color:#d6bbc1;margin-bottom:24px;}.bp-meta{background:#181216;border:1px solid #452129;border-radius:6px;padding:14px 18px;font-size:13px;margin-bottom:22px;}.bp-row{display:flex;justify-content:space-between;gap:16px;padding:5px 0;word-break:break-all;}.bp-label{color:#a8868e;flex-shrink:0;}.bp-val{color:#fde8ec;font-family:"SF Mono",Menlo,Consolas,monospace;text-align:right;}.bp-contact{font-size:13px;color:#c09ca4;line-height:1.7;border-top:1px solid #452129;padding-top:16px;}.bp-brand{margin-top:22px;font-size:12px;color:#7a5b62;text-align:center;letter-spacing:2px;}</style></head><body><div class="bp-card"><div class="bp-badge">高危安全拦截</div><h1>检测到异常攻击行为，访问已拒绝</h1><div class="bp-sub">Malicious Request Blocked</div><p class="bp-desc">安全防护网关检测到当前请求存在潜在恶意载荷或违规访问特征，已立即阻断并记录安全审计日志。</p><div class="bp-meta"><div class="bp-row"><span class="bp-label">请求编号</span><span class="bp-val">{{request_id}}</span></div><div class="bp-row"><span class="bp-label">发生时间</span><span class="bp-val">{{time}}</span></div><div class="bp-row"><span class="bp-label">客户端 IP</span><span class="bp-val">{{client_ip}}</span></div><div class="bp-row"><span class="bp-label">访问站点</span><span class="bp-val">{{domain}}</span></div><div class="bp-row"><span class="bp-label">状态码</span><span class="bp-val">{{status_code}}</span></div></div><p class="bp-contact">若您确认本次操作合规，请保存请求编号联系安全运营团队核查。</p><div class="bp-brand">九章动态安全防护网关</div></div></body></html>',
    403,
    'security_blocked',
    '请求触发安全防护策略，已被拦截',
    1,
    TRUE,
    'system',
    'system'
),
(
    '11111111-2222-4333-8444-555555550004',
    '友好频率限制提示页',
    '温和琥珀色提示样式，专为 CC 防护与 429 频率限制场景设计，含建议等待时间',
    'VISUAL',
    'amber_limit',
    '{"badge":"频率限制","title":"请求过于频繁，请稍后再试","subtitle":"Too Many Requests","description":"您当前的访问频率已超出站点限流阈值，系统已临时限制本次请求以保障服务稳定性，请稍候片刻后刷新重试。","contact_info":"如频繁出现此提示，请检查是否存在并发脚本或联系站点运维人员。","brand_name":"九章WEB应用智能防护系统","show_request_id":true,"show_timestamp":true,"show_client_ip":true,"show_domain":true,"show_status_code":true,"show_retry_after":true}'::jsonb,
    '',
    '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>请求过于频繁，请稍后再试</title><style>*{margin:0;padding:0;box-sizing:border-box;}body{font-family:"PingFang SC","Microsoft YaHei","Helvetica Neue",Arial,sans-serif;background:#fffbeb;color:#451a03;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;}.bp-card{max-width:580px;width:100%;background:#ffffff;border:1px solid #fde68a;border-top:4px solid #d97706;border-radius:12px;padding:38px 36px;box-shadow:0 10px 28px rgba(217,119,6,0.10);}.bp-badge{display:inline-block;background:#fef3c7;color:#b45309;border:1px solid #fcd34d;border-radius:999px;font-size:12px;font-weight:600;padding:4px 12px;margin-bottom:18px;}h1{font-size:22px;font-weight:600;margin-bottom:8px;color:#78350f;}.bp-sub{font-size:13px;color:#b45309;margin-bottom:14px;}.bp-desc{font-size:14px;line-height:1.8;color:#713f12;margin-bottom:24px;}.bp-meta{background:#fffbeb;border:1px solid #fde68a;border-radius:8px;padding:14px 18px;font-size:13px;margin-bottom:22px;}.bp-row{display:flex;justify-content:space-between;gap:16px;padding:5px 0;word-break:break-all;}.bp-label{color:#92400e;flex-shrink:0;}.bp-val{color:#451a03;font-family:"SF Mono",Menlo,Consolas,monospace;text-align:right;}.bp-contact{font-size:13px;color:#92400e;line-height:1.7;border-top:1px solid #fde68a;padding-top:16px;}.bp-brand{margin-top:22px;font-size:12px;color:#b45309;opacity:0.75;text-align:center;letter-spacing:1px;}</style></head><body><div class="bp-card"><div class="bp-badge">频率限制</div><h1>请求过于频繁，请稍后再试</h1><div class="bp-sub">Too Many Requests</div><p class="bp-desc">您当前的访问频率已超出站点限流阈值，系统已临时限制本次请求以保障服务稳定性，请稍候片刻后刷新重试。</p><div class="bp-meta"><div class="bp-row"><span class="bp-label">请求编号</span><span class="bp-val">{{request_id}}</span></div><div class="bp-row"><span class="bp-label">发生时间</span><span class="bp-val">{{time}}</span></div><div class="bp-row"><span class="bp-label">客户端 IP</span><span class="bp-val">{{client_ip}}</span></div><div class="bp-row"><span class="bp-label">访问站点</span><span class="bp-val">{{domain}}</span></div><div class="bp-row"><span class="bp-label">状态码</span><span class="bp-val">{{status_code}}</span></div><div class="bp-row"><span class="bp-label">建议等待（秒）</span><span class="bp-val">{{retry_after}}</span></div></div><p class="bp-contact">如频繁出现此提示，请检查是否存在并发脚本或联系站点运维人员。</p><div class="bp-brand">九章WEB应用智能防护系统</div></div></body></html>',
    429,
    'too_many_requests',
    '请求过于频繁，请稍后重试',
    1,
    TRUE,
    'system',
    'system'
)
ON CONFLICT (name) DO NOTHING;

-- 为内置模板补齐不可变 v1 版本历史
INSERT INTO block_page_versions (
    block_page_id, version, editor_mode, theme, visual_config, html_content, rendered_html,
    status_code, json_code, json_message, change_note, created_by
)
SELECT
    bp.id, bp.version, bp.editor_mode, bp.theme, bp.visual_config, bp.html_content, bp.rendered_html,
    bp.status_code, bp.json_code, bp.json_message, '系统内置初始版本', 'system'
FROM block_pages bp
WHERE bp.is_builtin = TRUE
ON CONFLICT (block_page_id, version) DO NOTHING;

-- e) 权限种子（遵循 000232 三权边界：业务防护策略归运维管理员 SECURITY_ADMIN，审计管理员 AUDIT_ADMIN 只读）
INSERT INTO permissions (code, name, module, description) VALUES
('block_pages.read', '查看自定义拦截页面', 'block_pages', '查看自定义拦截页面模板库、历史版本与全局/应用生效绑定'),
('block_pages.manage', '管理自定义拦截页面', 'block_pages', '创建、编辑、回滚、删除自定义拦截页面模板并配置全局或应用级生效绑定')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN ('block_pages.read', 'block_pages.manage')
ON CONFLICT (role_id, permission_id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'AUDIT_ADMIN' AND p.code IN ('block_pages.read')
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
