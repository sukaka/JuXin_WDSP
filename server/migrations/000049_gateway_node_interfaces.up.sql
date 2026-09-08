-- WDSP 阶段A 网口管理（docs/NETWORK_MODES_DESIGN.md §2.2）：节点物理网口清单与排序。
-- 网关周期性写 node-interfaces.jsonl 全量快照，服务端采集器 UPSERT 入库：
-- 保留用户已设定的 sort_order/role，新发现的口排末尾；清单中消失的口保留并置 present=false
-- （便于界面感知拔卡/改名）。权限点复用 system_health.read / system_settings.update，不新增。
BEGIN;

CREATE TABLE IF NOT EXISTS gateway_node_interfaces (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_name     VARCHAR(128) NOT NULL,
    ifname        VARCHAR(64)  NOT NULL,
    mac           VARCHAR(32)  NOT NULL DEFAULT '',
    pci_path      VARCHAR(64)  NOT NULL DEFAULT '',
    driver        VARCHAR(64)  NOT NULL DEFAULT '',
    media_type    VARCHAR(16)  NOT NULL DEFAULT 'UNKNOWN',
    link_speed    BIGINT       NOT NULL DEFAULT 0,
    operstate     VARCHAR(16)  NOT NULL DEFAULT '',
    sort_order    INT          NOT NULL DEFAULT 0,
    role          VARCHAR(32)  NOT NULL DEFAULT '',
    present       BOOLEAN      NOT NULL DEFAULT TRUE,
    first_seen_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_seen_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT chk_gw_node_iface_media_type CHECK (media_type IN ('TP', 'FIBRE', 'UNKNOWN'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_gw_node_ifaces_node_ifname
    ON gateway_node_interfaces (node_name, ifname);
CREATE INDEX IF NOT EXISTS idx_gw_node_ifaces_node_order
    ON gateway_node_interfaces (node_name, sort_order);

COMMIT;
