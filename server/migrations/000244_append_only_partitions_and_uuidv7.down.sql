-- 000244 回滚：恢复 11 张表为非分区表、恢复 gen_random_uuid() 默认值、
-- 恢复 api_authz_candidate_event_receipts -> api_runtime_events(id) 外键、移除新增索引与 uuid_generate_v7()。
-- 注意：执行于 database.Migrate BeginTx 事务内，不使用 CONCURRENTLY 与 BEGIN/COMMIT。

DO $$
DECLARE
    v_schema     TEXT := current_schema();
    v_relkind    CHAR;
    v_has_trgm   BOOLEAN;
    v_src_cnt    BIGINT;
    v_dst_cnt    BIGINT;
    v_seq_max    BIGINT;
    v_seq_last   BIGINT;
    v_seq_called BOOLEAN;
    v_has_fk     BOOLEAN;
    v_cols       TEXT;
BEGIN
    SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm') INTO v_has_trgm;

    -- 0. 移除新增的 api_authorization_decisions 时间索引并恢复既有分区表 id 默认值为 gen_random_uuid()
    EXECUTE format('DROP INDEX IF EXISTS %I.idx_api_authorization_decisions_occurred', v_schema);
    EXECUTE format('ALTER TABLE %I.security_events ALTER COLUMN id SET DEFAULT gen_random_uuid()', v_schema);
    EXECUTE format('ALTER TABLE %I.access_control_events ALTER COLUMN id SET DEFAULT gen_random_uuid()', v_schema);

    -- ==================== 1. access_logs ====================
    SELECT c.relkind INTO v_relkind
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = v_schema AND c.relname = 'access_logs';

    IF v_relkind = 'p' THEN
        EXECUTE format('LOCK TABLE %I.access_logs IN ACCESS EXCLUSIVE MODE', v_schema);
        EXECUTE format($sql$
            CREATE TABLE %I._m244_u_access_logs (
                id                      UUID NOT NULL DEFAULT gen_random_uuid(),
                occurred_at             TIMESTAMPTZ  NOT NULL,
                request_id              VARCHAR(64)  NOT NULL DEFAULT '',
                application_id          UUID,
                domain                  VARCHAR(255) NOT NULL DEFAULT '',
                gateway_node_id         VARCHAR(64)  NOT NULL DEFAULT '',
                client_ip               INET,
                client_port             INTEGER,
                request_method          VARCHAR(16)  NOT NULL DEFAULT '',
                request_uri             TEXT         NOT NULL DEFAULT '',
                request_path            TEXT         NOT NULL DEFAULT '',
                query_summary           TEXT         NOT NULL DEFAULT '',
                http_version            VARCHAR(16)  NOT NULL DEFAULT '',
                content_type            VARCHAR(255) NOT NULL DEFAULT '',
                user_agent_summary      VARCHAR(512) NOT NULL DEFAULT '',
                referer_summary         VARCHAR(512) NOT NULL DEFAULT '',
                response_status         INTEGER      NOT NULL DEFAULT 0,
                bytes_in                BIGINT       NOT NULL DEFAULT 0,
                bytes_out               BIGINT       NOT NULL DEFAULT 0,
                duration_ms             INTEGER      NOT NULL DEFAULT 0,
                waf_action              VARCHAR(32)  NOT NULL DEFAULT '',
                request_headers         JSONB        NOT NULL DEFAULT '{}',
                request_body            TEXT         NOT NULL DEFAULT '',
                request_body_truncated  BOOLEAN      NOT NULL DEFAULT FALSE,
                response_headers        JSONB        NOT NULL DEFAULT '{}',
                response_body           TEXT         NOT NULL DEFAULT '',
                response_body_truncated BOOLEAN      NOT NULL DEFAULT FALSE,
                created_at              TIMESTAMPTZ  NOT NULL DEFAULT now(),
                trace_id                TEXT,
                span_id                 TEXT,
                endpoint_key            TEXT,
                path_template           TEXT,
                ttfb_ms                 INTEGER,
                client_ip_source        VARCHAR(32),
                trusted_proxy_used      VARCHAR(128),
                forwarded_chain_summary VARCHAR(256),
                tls_protocol            VARCHAR(24)  NOT NULL DEFAULT '',
                tls_cipher_suite        VARCHAR(64)  NOT NULL DEFAULT '',
                tls_is_gm               BOOLEAN      NOT NULL DEFAULT FALSE,
                tls_ja3                 VARCHAR(64)  NOT NULL DEFAULT '',
                client_hello_version    VARCHAR(24)  NOT NULL DEFAULT '',
                CONSTRAINT _m244_old_access_logs_pkey PRIMARY KEY (id)
            )
        $sql$, v_schema);

        v_cols := 'id, occurred_at, request_id, application_id, domain, gateway_node_id, client_ip, client_port, request_method, request_uri, request_path, query_summary, http_version, content_type, user_agent_summary, referer_summary, response_status, bytes_in, bytes_out, duration_ms, waf_action, request_headers, request_body, request_body_truncated, response_headers, response_body, response_body_truncated, created_at, trace_id, span_id, endpoint_key, path_template, ttfb_ms, client_ip_source, trusted_proxy_used, forwarded_chain_summary, tls_protocol, tls_cipher_suite, tls_is_gm, tls_ja3, client_hello_version';

        EXECUTE format('SELECT count(*) FROM %I.access_logs', v_schema) INTO v_src_cnt;
        EXECUTE format('INSERT INTO %I._m244_u_access_logs (%s) SELECT %s FROM %I.access_logs', v_schema, v_cols, v_cols, v_schema);
        GET DIAGNOSTICS v_dst_cnt = ROW_COUNT;
        IF v_src_cnt <> v_dst_cnt THEN
            RAISE EXCEPTION 'rollback row count mismatch on access_logs: src %, dst %', v_src_cnt, v_dst_cnt;
        END IF;

        EXECUTE format('DROP TABLE %I.access_logs', v_schema);
        EXECUTE format('ALTER TABLE %I._m244_u_access_logs RENAME TO access_logs', v_schema);
        EXECUTE format('ALTER TABLE %I.access_logs RENAME CONSTRAINT _m244_old_access_logs_pkey TO access_logs_pkey', v_schema);

        -- 跨日分区的同 request_id 行在回滚至单列部分唯一索引前按最新行去重
        EXECUTE format($sql$
            DELETE FROM %I.access_logs a USING (
                SELECT ctid, row_number() OVER (PARTITION BY request_id ORDER BY occurred_at DESC, created_at DESC, id DESC) AS rn
                FROM %I.access_logs
                WHERE request_id <> ''
            ) d
            WHERE a.ctid = d.ctid AND d.rn > 1
        $sql$, v_schema, v_schema);

        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_access_logs_occurred_at ON %I.access_logs (occurred_at DESC)', v_schema);
        EXECUTE format('CREATE UNIQUE INDEX IF NOT EXISTS idx_access_logs_request_id ON %I.access_logs (request_id) WHERE request_id <> ''''', v_schema);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_access_logs_trace_id ON %I.access_logs (trace_id) WHERE trace_id IS NOT NULL', v_schema);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_access_logs_app_occurred ON %I.access_logs (application_id, occurred_at) WHERE application_id IS NOT NULL', v_schema);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_access_logs_client_ip_occurred ON %I.access_logs (client_ip, occurred_at DESC) WHERE client_ip IS NOT NULL', v_schema);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_access_logs_endpoint_occurred ON %I.access_logs (endpoint_key, occurred_at DESC) WHERE endpoint_key IS NOT NULL AND endpoint_key <> ''''', v_schema);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_access_logs_waf_action_occurred ON %I.access_logs (waf_action, occurred_at DESC) WHERE waf_action <> '''' AND waf_action <> ''ALLOW''', v_schema);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_access_logs_status_err_occurred ON %I.access_logs (response_status, occurred_at DESC) WHERE response_status >= 400', v_schema);
        IF v_has_trgm THEN
            EXECUTE format('CREATE INDEX IF NOT EXISTS idx_access_logs_domain_trgm ON %I.access_logs USING GIN (domain gin_trgm_ops)', v_schema);
            EXECUTE format('CREATE INDEX IF NOT EXISTS idx_access_logs_uri_trgm ON %I.access_logs USING GIN (request_uri gin_trgm_ops)', v_schema);
        END IF;

        EXECUTE format('COMMENT ON COLUMN %I.access_logs.client_ip_source IS ''真实客户端 IP 识别来源（CONNECTION/X_FORWARDED_FOR/X_REAL_IP/FORWARDED/CUSTOM_HEADER）；NULL = 旧版网关未上报''', v_schema);
        EXECUTE format('COMMENT ON COLUMN %I.access_logs.trusted_proxy_used IS ''命中的可信代理名；NULL/空 = 未经过可信代理解析''', v_schema);
        EXECUTE format('COMMENT ON COLUMN %I.access_logs.forwarded_chain_summary IS ''截断的代理链摘要（伪造/非法头场景为原始头值截断片段）；NULL = 无代理链''', v_schema);
        EXECUTE format('COMMENT ON COLUMN %I.access_logs.tls_protocol IS ''实际协商的 TLS/TLCP 协议版本（TLCP1.1/TLS1.0~1.3）；明文 HTTP 或旧数据为空串''', v_schema);
        EXECUTE format('COMMENT ON COLUMN %I.access_logs.tls_cipher_suite IS ''实际协商的密码套件名称（含国密 SM4/SM3 与国际标准套件）；明文 HTTP 或旧数据为空串''', v_schema);
        EXECUTE format('COMMENT ON COLUMN %I.access_logs.tls_is_gm IS ''是否国密加密会话（SM2/TLCP1.1）；默认 FALSE''', v_schema);
        EXECUTE format('COMMENT ON COLUMN %I.access_logs.tls_ja3 IS ''客户端 ClientHello JA3 指纹（32 位小写 MD5 十六进制）；明文 HTTP 或旧数据为空串''', v_schema);
        EXECUTE format('COMMENT ON COLUMN %I.access_logs.client_hello_version IS ''ClientHello 原始检测版本（SSLv2/SSLv2/v3/SSLv3/TLS1.0~1.3/TLCP1.1）；明文 HTTP 或旧数据为空串''', v_schema);
    END IF;

    -- ==================== 2. tls_handshake_events ====================
    SELECT c.relkind INTO v_relkind
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = v_schema AND c.relname = 'tls_handshake_events';

    IF v_relkind = 'p' THEN
        EXECUTE format('LOCK TABLE %I.tls_handshake_events IN ACCESS EXCLUSIVE MODE', v_schema);
        EXECUTE format($sql$
            CREATE TABLE %I._m244_u_tls_handshake_events (
                id                  UUID        NOT NULL DEFAULT gen_random_uuid(),
                occurred_at         TIMESTAMPTZ NOT NULL,
                gateway_node_id     VARCHAR(64) NOT NULL DEFAULT '',
                application_id      UUID,
                sni                 VARCHAR(255) NOT NULL DEFAULT '',
                client_ip           VARCHAR(64) NOT NULL DEFAULT '',
                client_port         INTEGER     NOT NULL DEFAULT 0,
                server_port         INTEGER     NOT NULL DEFAULT 0,
                detected_protocol   VARCHAR(24) NOT NULL DEFAULT 'UNKNOWN',
                negotiated_protocol VARCHAR(24) NOT NULL DEFAULT '',
                cipher_suite        VARCHAR(64) NOT NULL DEFAULT '',
                is_gm               BOOLEAN     NOT NULL DEFAULT FALSE,
                ja3_hash            VARCHAR(64) NOT NULL DEFAULT '',
                alpn                VARCHAR(64) NOT NULL DEFAULT '',
                action              VARCHAR(32) NOT NULL DEFAULT 'ALLOWED'
                                    CONSTRAINT tls_handshake_events_action_check
                                    CHECK (action IN ('ALLOWED', 'BLOCKED_LEGACY_SSL', 'BLOCKED_PROTOCOL_POLICY', 'HANDSHAKE_FAILED')),
                error_reason        VARCHAR(512) NOT NULL DEFAULT '',
                created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
                CONSTRAINT _m244_old_tls_handshake_events_pkey PRIMARY KEY (id)
            )
        $sql$, v_schema);

        v_cols := 'id, occurred_at, gateway_node_id, application_id, sni, client_ip, client_port, server_port, detected_protocol, negotiated_protocol, cipher_suite, is_gm, ja3_hash, alpn, action, error_reason, created_at';

        EXECUTE format('SELECT count(*) FROM %I.tls_handshake_events', v_schema) INTO v_src_cnt;
        EXECUTE format('INSERT INTO %I._m244_u_tls_handshake_events (%s) SELECT %s FROM %I.tls_handshake_events', v_schema, v_cols, v_cols, v_schema);
        GET DIAGNOSTICS v_dst_cnt = ROW_COUNT;
        IF v_src_cnt <> v_dst_cnt THEN
            RAISE EXCEPTION 'rollback row count mismatch on tls_handshake_events: src %, dst %', v_src_cnt, v_dst_cnt;
        END IF;

        EXECUTE format('DROP TABLE %I.tls_handshake_events', v_schema);
        EXECUTE format('ALTER TABLE %I._m244_u_tls_handshake_events RENAME TO tls_handshake_events', v_schema);
        EXECUTE format('ALTER TABLE %I.tls_handshake_events RENAME CONSTRAINT _m244_old_tls_handshake_events_pkey TO tls_handshake_events_pkey', v_schema);

        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_tls_handshake_events_occurred_at ON %I.tls_handshake_events (occurred_at DESC)', v_schema);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_tls_handshake_events_protocol_occurred ON %I.tls_handshake_events (detected_protocol, occurred_at DESC)', v_schema);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_tls_handshake_events_action_occurred ON %I.tls_handshake_events (action, occurred_at DESC)', v_schema);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_tls_handshake_events_sni_occurred ON %I.tls_handshake_events (sni, occurred_at DESC)', v_schema);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_tls_handshake_events_app_occurred ON %I.tls_handshake_events (application_id, occurred_at DESC)', v_schema);
        IF v_has_trgm THEN
            EXECUTE format('CREATE INDEX IF NOT EXISTS idx_tls_handshake_events_sni_trgm ON %I.tls_handshake_events USING GIN (sni gin_trgm_ops)', v_schema);
        END IF;

        EXECUTE format('COMMENT ON TABLE %I.tls_handshake_events IS ''SSL/TLS/国密 TLCP 加密会话分析握手事件表（网关 jiuzhang_tls_mux JSONL 采集入库）''', v_schema);
    END IF;

    -- ==================== 3. agent_http_events ====================
    SELECT c.relkind INTO v_relkind
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = v_schema AND c.relname = 'agent_http_events';

    IF v_relkind = 'p' THEN
        EXECUTE format('LOCK TABLE %I.agent_http_events IN ACCESS EXCLUSIVE MODE', v_schema);
        EXECUTE format('ALTER SEQUENCE IF EXISTS %I.agent_http_events_id_seq OWNED BY NONE', v_schema);

        EXECUTE format($sql$
            CREATE TABLE %I._m244_u_agent_http_events (
                id                          BIGINT       NOT NULL DEFAULT nextval('%I.agent_http_events_id_seq'::regclass),
                agent_id                    UUID         NOT NULL,
                flow_id                     VARCHAR(255) NOT NULL DEFAULT '',
                ts                          TIMESTAMPTZ  NOT NULL,
                latency_ms                  INT,
                src_ip                      VARCHAR(64)  NOT NULL DEFAULT '',
                src_port                    INT          NOT NULL DEFAULT 0,
                dst_ip                      VARCHAR(64)  NOT NULL DEFAULT '',
                dst_port                    INT          NOT NULL DEFAULT 0,
                direction                   VARCHAR(16)  NOT NULL
                                            CONSTRAINT agent_http_events_direction_check
                                            CHECK (direction IN ('ingress', 'egress', 'both')),
                tls_visibility              VARCHAR(16)  NOT NULL DEFAULT 'PLAINTEXT'
                                            CONSTRAINT agent_http_events_tls_visibility_check
                                            CHECK (tls_visibility IN ('PLAINTEXT', 'ENCRYPTED', 'DECRYPTED', 'UNKNOWN')),
                method                      VARCHAR(16)  NOT NULL DEFAULT '',
                scheme                      VARCHAR(8)   NOT NULL DEFAULT 'http',
                host                        VARCHAR(255) NOT NULL DEFAULT '',
                uri                         TEXT         NOT NULL DEFAULT '',
                status                      INT,
                request_headers             JSONB        NOT NULL DEFAULT '{}'::jsonb,
                response_headers            JSONB,
                request_body                TEXT,
                response_body               TEXT,
                req_truncated               BOOLEAN      NOT NULL DEFAULT false,
                resp_truncated              BOOLEAN      NOT NULL DEFAULT false,
                req_original_size           BIGINT       NOT NULL DEFAULT 0,
                resp_original_size          BIGINT       NOT NULL DEFAULT 0,
                created_at                  TIMESTAMPTZ  NOT NULL DEFAULT now(),
                req_skipped_reason          TEXT         NOT NULL DEFAULT '',
                resp_skipped_reason         TEXT         NOT NULL DEFAULT '',
                k8s                         JSONB        NULL,
                schema_version              SMALLINT     NOT NULL DEFAULT 1
                                            CONSTRAINT agent_http_events_schema_version_check
                                            CHECK (schema_version IN (1, 2)),
                event_id                    VARCHAR(128) NULL,
                source_type                 VARCHAR(16)  NOT NULL DEFAULT 'PASSIVE_HTTP1'
                                            CONSTRAINT agent_http_events_source_type_check
                                            CHECK (source_type IN ('PASSIVE_HTTP1', 'NGINX_MIRROR', 'ENVOY_TAP')),
                source_instance             VARCHAR(255) NOT NULL DEFAULT '',
                source_epoch                BIGINT       NOT NULL DEFAULT 0,
                source_capabilities_version VARCHAR(64)  NOT NULL DEFAULT '',
                observed_http_version       VARCHAR(8)   NOT NULL DEFAULT 'UNKNOWN'
                                            CONSTRAINT agent_http_events_observed_http_version_check
                                            CHECK (observed_http_version IN ('1.0', '1.1', '2', '3', 'UNKNOWN')),
                original_http_version       VARCHAR(8)   NULL
                                            CONSTRAINT agent_http_events_original_http_version_check
                                            CHECK (original_http_version IN ('1.0', '1.1', '2', '3', 'UNKNOWN')),
                association_state           VARCHAR(16)  NULL
                                            CONSTRAINT agent_http_events_association_state_check
                                            CHECK (association_state IN ('COMPLETE', 'REQUEST_ONLY', 'PARTIAL', 'UNCORRELATED')),
                association_reason          VARCHAR(64)  NOT NULL DEFAULT '',
                capture_stream_id           VARCHAR(255) NULL,
                application_binding_id      UUID         NULL,
                binding_version             BIGINT       NULL,
                grpc                        JSONB        NULL,
                request_trailers            JSONB        NULL,
                response_trailers           JSONB        NULL,
                req_body_quality            JSONB        NULL,
                resp_body_quality           JSONB        NULL,
                collection_ts               TIMESTAMPTZ  NULL,
                ingestion_ts                TIMESTAMPTZ  NULL,
                CONSTRAINT _m244_old_agent_http_events_pkey PRIMARY KEY (id),
                CONSTRAINT agent_http_events_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES %I.agents(agent_id) ON DELETE CASCADE
            )
        $sql$, v_schema, v_schema, v_schema);

        v_cols := 'id, agent_id, flow_id, ts, latency_ms, src_ip, src_port, dst_ip, dst_port, direction, tls_visibility, method, scheme, host, uri, status, request_headers, response_headers, request_body, response_body, req_truncated, resp_truncated, req_original_size, resp_original_size, created_at, req_skipped_reason, resp_skipped_reason, k8s, schema_version, event_id, source_type, source_instance, source_epoch, source_capabilities_version, observed_http_version, original_http_version, association_state, association_reason, capture_stream_id, application_binding_id, binding_version, grpc, request_trailers, response_trailers, req_body_quality, resp_body_quality, collection_ts, ingestion_ts';

        EXECUTE format('SELECT count(*) FROM %I.agent_http_events', v_schema) INTO v_src_cnt;
        EXECUTE format('INSERT INTO %I._m244_u_agent_http_events (%s) SELECT %s FROM %I.agent_http_events', v_schema, v_cols, v_cols, v_schema);
        GET DIAGNOSTICS v_dst_cnt = ROW_COUNT;
        IF v_src_cnt <> v_dst_cnt THEN
            RAISE EXCEPTION 'rollback row count mismatch on agent_http_events: src %, dst %', v_src_cnt, v_dst_cnt;
        END IF;

        EXECUTE format('DROP TABLE %I.agent_http_events', v_schema);
        EXECUTE format('ALTER TABLE %I._m244_u_agent_http_events RENAME TO agent_http_events', v_schema);
        EXECUTE format('ALTER TABLE %I.agent_http_events RENAME CONSTRAINT _m244_old_agent_http_events_pkey TO agent_http_events_pkey', v_schema);

        EXECUTE format('ALTER SEQUENCE %I.agent_http_events_id_seq OWNED BY %I.agent_http_events.id', v_schema, v_schema);
        EXECUTE format('SELECT COALESCE(MAX(id), 0) FROM %I.agent_http_events', v_schema) INTO v_seq_max;
        EXECUTE format('SELECT last_value, is_called FROM %I.agent_http_events_id_seq', v_schema) INTO v_seq_last, v_seq_called;
        IF v_seq_max > 0 OR v_seq_called THEN
            PERFORM setval(format('%I.agent_http_events_id_seq', v_schema)::regclass, GREATEST(v_seq_max, v_seq_last, 1), true);
        END IF;

        -- 跨日分区的同 (agent_id, event_id) 行在回滚至两列部分唯一索引前按最新行去重
        EXECUTE format($sql$
            DELETE FROM %I.agent_http_events a USING (
                SELECT ctid, row_number() OVER (PARTITION BY agent_id, event_id ORDER BY ts DESC, created_at DESC, id DESC) AS rn
                FROM %I.agent_http_events
                WHERE event_id IS NOT NULL
            ) d
            WHERE a.ctid = d.ctid AND d.rn > 1
        $sql$, v_schema, v_schema);

        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_agent_http_events_agent_ts ON %I.agent_http_events (agent_id, ts DESC)', v_schema);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_agent_http_events_host_uri ON %I.agent_http_events (host, uri)', v_schema);
        EXECUTE format('CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_http_events_event_id ON %I.agent_http_events (agent_id, event_id) WHERE event_id IS NOT NULL', v_schema);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_agent_http_events_grpc_ts ON %I.agent_http_events (ts DESC) WHERE grpc IS NOT NULL', v_schema);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_agent_http_events_created_at ON %I.agent_http_events (created_at)', v_schema);
    END IF;

    -- ==================== 4. agent_flow_events ====================
    SELECT c.relkind INTO v_relkind
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = v_schema AND c.relname = 'agent_flow_events';

    IF v_relkind = 'p' THEN
        EXECUTE format('LOCK TABLE %I.agent_flow_events IN ACCESS EXCLUSIVE MODE', v_schema);
        EXECUTE format('ALTER SEQUENCE IF EXISTS %I.agent_flow_events_id_seq OWNED BY NONE', v_schema);

        EXECUTE format($sql$
            CREATE TABLE %I._m244_u_agent_flow_events (
                id             BIGINT       NOT NULL DEFAULT nextval('%I.agent_flow_events_id_seq'::regclass),
                agent_id       UUID         NOT NULL,
                ts             TIMESTAMPTZ  NOT NULL,
                event_type     VARCHAR(16)  NOT NULL
                               CONSTRAINT agent_flow_events_event_type_check
                               CHECK (event_type IN ('request', 'flow_end')),
                flow_id        VARCHAR(255) NOT NULL DEFAULT '',
                src_ip         VARCHAR(64)  NOT NULL DEFAULT '',
                src_port       INT          NOT NULL DEFAULT 0,
                dst_ip         VARCHAR(64)  NOT NULL DEFAULT '',
                dst_port       INT          NOT NULL DEFAULT 0,
                protocol       VARCHAR(16)  NOT NULL DEFAULT 'tcp',
                direction      VARCHAR(16)  NOT NULL DEFAULT '',
                bytes_in       BIGINT       NOT NULL DEFAULT 0,
                bytes_out      BIGINT       NOT NULL DEFAULT 0,
                packets_in     BIGINT       NOT NULL DEFAULT 0,
                packets_out    BIGINT       NOT NULL DEFAULT 0,
                tls_visibility VARCHAR(16)  NOT NULL DEFAULT ''
                               CONSTRAINT agent_flow_events_tls_visibility_check
                               CHECK (tls_visibility IN ('', 'PLAINTEXT', 'ENCRYPTED', 'UNKNOWN')),
                http_method    VARCHAR(16)  NOT NULL DEFAULT '',
                http_host      VARCHAR(255) NOT NULL DEFAULT '',
                http_uri       TEXT         NOT NULL DEFAULT '',
                http_status    INT          NOT NULL DEFAULT 0,
                created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
                k8s            JSONB        NULL,
                CONSTRAINT _m244_old_agent_flow_events_pkey PRIMARY KEY (id),
                CONSTRAINT agent_flow_events_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES %I.agents(agent_id) ON DELETE CASCADE
            )
        $sql$, v_schema, v_schema, v_schema);

        v_cols := 'id, agent_id, ts, event_type, flow_id, src_ip, src_port, dst_ip, dst_port, protocol, direction, bytes_in, bytes_out, packets_in, packets_out, tls_visibility, http_method, http_host, http_uri, http_status, created_at, k8s';

        EXECUTE format('SELECT count(*) FROM %I.agent_flow_events', v_schema) INTO v_src_cnt;
        EXECUTE format('INSERT INTO %I._m244_u_agent_flow_events (%s) SELECT %s FROM %I.agent_flow_events', v_schema, v_cols, v_cols, v_schema);
        GET DIAGNOSTICS v_dst_cnt = ROW_COUNT;
        IF v_src_cnt <> v_dst_cnt THEN
            RAISE EXCEPTION 'rollback row count mismatch on agent_flow_events: src %, dst %', v_src_cnt, v_dst_cnt;
        END IF;

        EXECUTE format('DROP TABLE %I.agent_flow_events', v_schema);
        EXECUTE format('ALTER TABLE %I._m244_u_agent_flow_events RENAME TO agent_flow_events', v_schema);
        EXECUTE format('ALTER TABLE %I.agent_flow_events RENAME CONSTRAINT _m244_old_agent_flow_events_pkey TO agent_flow_events_pkey', v_schema);

        EXECUTE format('ALTER SEQUENCE %I.agent_flow_events_id_seq OWNED BY %I.agent_flow_events.id', v_schema, v_schema);
        EXECUTE format('SELECT COALESCE(MAX(id), 0) FROM %I.agent_flow_events', v_schema) INTO v_seq_max;
        EXECUTE format('SELECT last_value, is_called FROM %I.agent_flow_events_id_seq', v_schema) INTO v_seq_last, v_seq_called;
        IF v_seq_max > 0 OR v_seq_called THEN
            PERFORM setval(format('%I.agent_flow_events_id_seq', v_schema)::regclass, GREATEST(v_seq_max, v_seq_last, 1), true);
        END IF;

        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_agent_flow_events_agent_ts ON %I.agent_flow_events (agent_id, ts DESC)', v_schema);
    END IF;

    -- ==================== 5. metric_minute_aggregates ====================
    SELECT c.relkind INTO v_relkind
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = v_schema AND c.relname = 'metric_minute_aggregates';

    IF v_relkind = 'p' THEN
        EXECUTE format('LOCK TABLE %I.metric_minute_aggregates IN ACCESS EXCLUSIVE MODE', v_schema);
        EXECUTE format($sql$
            CREATE TABLE %I._m244_u_metric_minute_aggregates (
                bucket_start TIMESTAMPTZ      NOT NULL,
                metric       VARCHAR(64)      NOT NULL,
                labels       JSONB            NOT NULL DEFAULT '{}',
                value        DOUBLE PRECISION NOT NULL DEFAULT 0,
                extra        JSONB            NOT NULL DEFAULT '{}',
                updated_at   TIMESTAMPTZ      NOT NULL DEFAULT now(),
                CONSTRAINT _m244_old_metric_minute_aggregates_pkey PRIMARY KEY (bucket_start, metric, labels)
            )
        $sql$, v_schema);

        v_cols := 'bucket_start, metric, labels, value, extra, updated_at';

        EXECUTE format('SELECT count(*) FROM %I.metric_minute_aggregates', v_schema) INTO v_src_cnt;
        EXECUTE format('INSERT INTO %I._m244_u_metric_minute_aggregates (%s) SELECT %s FROM %I.metric_minute_aggregates', v_schema, v_cols, v_cols, v_schema);
        GET DIAGNOSTICS v_dst_cnt = ROW_COUNT;
        IF v_src_cnt <> v_dst_cnt THEN
            RAISE EXCEPTION 'rollback row count mismatch on metric_minute_aggregates: src %, dst %', v_src_cnt, v_dst_cnt;
        END IF;

        EXECUTE format('DROP TABLE %I.metric_minute_aggregates', v_schema);
        EXECUTE format('ALTER TABLE %I._m244_u_metric_minute_aggregates RENAME TO metric_minute_aggregates', v_schema);
        EXECUTE format('ALTER TABLE %I.metric_minute_aggregates RENAME CONSTRAINT _m244_old_metric_minute_aggregates_pkey TO metric_minute_aggregates_pkey', v_schema);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_mma_metric_time ON %I.metric_minute_aggregates (metric, bucket_start DESC)', v_schema);
    END IF;

    -- ==================== 6. source_ip_summaries ====================
    SELECT c.relkind INTO v_relkind
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = v_schema AND c.relname = 'source_ip_summaries';

    IF v_relkind = 'p' THEN
        EXECUTE format('LOCK TABLE %I.source_ip_summaries IN ACCESS EXCLUSIVE MODE', v_schema);
        EXECUTE format($sql$
            CREATE TABLE %I._m244_u_source_ip_summaries (
                bucket_start TIMESTAMPTZ NOT NULL,
                client_ip    INET        NOT NULL,
                waf_events   BIGINT      NOT NULL DEFAULT 0,
                cc_events    BIGINT      NOT NULL DEFAULT 0,
                deny_hits    BIGINT      NOT NULL DEFAULT 0,
                last_seen_at TIMESTAMPTZ,
                updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
                CONSTRAINT _m244_old_source_ip_summaries_pkey PRIMARY KEY (bucket_start, client_ip)
            )
        $sql$, v_schema);

        v_cols := 'bucket_start, client_ip, waf_events, cc_events, deny_hits, last_seen_at, updated_at';

        EXECUTE format('SELECT count(*) FROM %I.source_ip_summaries', v_schema) INTO v_src_cnt;
        EXECUTE format('INSERT INTO %I._m244_u_source_ip_summaries (%s) SELECT %s FROM %I.source_ip_summaries', v_schema, v_cols, v_cols, v_schema);
        GET DIAGNOSTICS v_dst_cnt = ROW_COUNT;
        IF v_src_cnt <> v_dst_cnt THEN
            RAISE EXCEPTION 'rollback row count mismatch on source_ip_summaries: src %, dst %', v_src_cnt, v_dst_cnt;
        END IF;

        EXECUTE format('DROP TABLE %I.source_ip_summaries', v_schema);
        EXECUTE format('ALTER TABLE %I._m244_u_source_ip_summaries RENAME TO source_ip_summaries', v_schema);
        EXECUTE format('ALTER TABLE %I.source_ip_summaries RENAME CONSTRAINT _m244_old_source_ip_summaries_pkey TO source_ip_summaries_pkey', v_schema);
    END IF;

    -- ==================== 7. uri_security_summaries ====================
    SELECT c.relkind INTO v_relkind
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = v_schema AND c.relname = 'uri_security_summaries';

    IF v_relkind = 'p' THEN
        EXECUTE format('LOCK TABLE %I.uri_security_summaries IN ACCESS EXCLUSIVE MODE', v_schema);
        EXECUTE format($sql$
            CREATE TABLE %I._m244_u_uri_security_summaries (
                bucket_start     TIMESTAMPTZ  NOT NULL,
                application_code VARCHAR(64)  NOT NULL DEFAULT '',
                uri_path         VARCHAR(255) NOT NULL DEFAULT '',
                waf_events       BIGINT       NOT NULL DEFAULT 0,
                cc_events        BIGINT       NOT NULL DEFAULT 0,
                updated_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
                waf_blocks       BIGINT       NOT NULL DEFAULT 0,
                CONSTRAINT _m244_old_uri_security_summaries_pkey PRIMARY KEY (bucket_start, application_code, uri_path)
            )
        $sql$, v_schema);

        v_cols := 'bucket_start, application_code, uri_path, waf_events, cc_events, updated_at, waf_blocks';

        EXECUTE format('SELECT count(*) FROM %I.uri_security_summaries', v_schema) INTO v_src_cnt;
        EXECUTE format('INSERT INTO %I._m244_u_uri_security_summaries (%s) SELECT %s FROM %I.uri_security_summaries', v_schema, v_cols, v_cols, v_schema);
        GET DIAGNOSTICS v_dst_cnt = ROW_COUNT;
        IF v_src_cnt <> v_dst_cnt THEN
            RAISE EXCEPTION 'rollback row count mismatch on uri_security_summaries: src %, dst %', v_src_cnt, v_dst_cnt;
        END IF;

        EXECUTE format('DROP TABLE %I.uri_security_summaries', v_schema);
        EXECUTE format('ALTER TABLE %I._m244_u_uri_security_summaries RENAME TO uri_security_summaries', v_schema);
        EXECUTE format('ALTER TABLE %I.uri_security_summaries RENAME CONSTRAINT _m244_old_uri_security_summaries_pkey TO uri_security_summaries_pkey', v_schema);
    END IF;

    -- ==================== 8. api_runtime_events + 恢复外键 ====================
    SELECT c.relkind INTO v_relkind
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = v_schema AND c.relname = 'api_runtime_events';

    IF v_relkind = 'p' THEN
        EXECUTE format('LOCK TABLE %I.api_runtime_events IN ACCESS EXCLUSIVE MODE', v_schema);
        EXECUTE format($sql$
            CREATE TABLE %I._m244_u_api_runtime_events (
                id                   UUID         NOT NULL DEFAULT gen_random_uuid(),
                request_id           VARCHAR(64)  NOT NULL,
                endpoint_key         VARCHAR(560) NOT NULL DEFAULT '',
                risk_score           INTEGER      NOT NULL DEFAULT 0,
                risk_level           VARCHAR(32)  NOT NULL DEFAULT 'NONE',
                final_action         VARCHAR(32)  NOT NULL DEFAULT 'ALLOW',
                details_json         JSONB        NOT NULL DEFAULT '[]',
                occurred_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
                identity_fingerprint VARCHAR(128) NOT NULL DEFAULT '',
                auth_type            VARCHAR(32)  NOT NULL DEFAULT '',
                response_status      INTEGER      NOT NULL DEFAULT 0,
                client_ip            TEXT,
                method               TEXT,
                raw_path             TEXT,
                latency_ms           BIGINT,
                model_version        TEXT,
                policy_version       TEXT,
                gateway_node         TEXT,
                jwt_verification     JSONB,
                final_decision       JSONB,
                api_level            VARCHAR(32)
                                     CONSTRAINT chk_api_runtime_events_api_level
                                     CHECK (api_level IS NULL OR api_level IN ('CONFIRMED_API','PROBABLE_API','POSSIBLE_API','NON_API')),
                device_fingerprint   VARCHAR(64),
                object_identifiers   JSONB,
                application_id       UUID,
                trace_id             VARCHAR(32)
                                     CONSTRAINT chk_api_runtime_events_trace_id
                                     CHECK (trace_id IS NULL OR (trace_id ~ '^[0-9a-f]{32}$' AND trace_id <> '00000000000000000000000000000000')),
                CONSTRAINT _m244_old_api_runtime_events_pkey PRIMARY KEY (id)
            )
        $sql$, v_schema);

        v_cols := 'id, request_id, endpoint_key, risk_score, risk_level, final_action, details_json, occurred_at, identity_fingerprint, auth_type, response_status, client_ip, method, raw_path, latency_ms, model_version, policy_version, gateway_node, jwt_verification, final_decision, api_level, device_fingerprint, object_identifiers, application_id, trace_id';

        EXECUTE format('SELECT count(*) FROM %I.api_runtime_events', v_schema) INTO v_src_cnt;
        EXECUTE format('INSERT INTO %I._m244_u_api_runtime_events (%s) SELECT %s FROM %I.api_runtime_events', v_schema, v_cols, v_cols, v_schema);
        GET DIAGNOSTICS v_dst_cnt = ROW_COUNT;
        IF v_src_cnt <> v_dst_cnt THEN
            RAISE EXCEPTION 'rollback row count mismatch on api_runtime_events: src %, dst %', v_src_cnt, v_dst_cnt;
        END IF;

        EXECUTE format('DROP TABLE %I.api_runtime_events', v_schema);
        EXECUTE format('ALTER TABLE %I._m244_u_api_runtime_events RENAME TO api_runtime_events', v_schema);
        EXECUTE format('ALTER TABLE %I.api_runtime_events RENAME CONSTRAINT _m244_old_api_runtime_events_pkey TO api_runtime_events_pkey', v_schema);

        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_api_runtime_events_request ON %I.api_runtime_events (request_id)', v_schema);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_api_runtime_events_time ON %I.api_runtime_events (occurred_at DESC)', v_schema);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_api_runtime_events_node ON %I.api_runtime_events (gateway_node, occurred_at DESC)', v_schema);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_api_runtime_events_app_device_time ON %I.api_runtime_events (application_id, device_fingerprint, occurred_at DESC) WHERE application_id IS NOT NULL AND device_fingerprint IS NOT NULL', v_schema);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_api_runtime_events_trace_id ON %I.api_runtime_events (trace_id) WHERE trace_id IS NOT NULL', v_schema);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_api_runtime_events_endpoint_occurred ON %I.api_runtime_events (endpoint_key, occurred_at DESC)', v_schema);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_api_runtime_events_identity_occurred ON %I.api_runtime_events (identity_fingerprint, occurred_at DESC) WHERE identity_fingerprint <> ''''', v_schema);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_api_runtime_events_final_action_occurred ON %I.api_runtime_events (final_action, occurred_at DESC) WHERE final_action <> '''' AND final_action <> ''ALLOW''', v_schema);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_api_runtime_events_details_gin ON %I.api_runtime_events USING GIN (details_json jsonb_path_ops)', v_schema);

        EXECUTE format('COMMENT ON COLUMN %I.api_runtime_events.application_id IS ''网关已识别的应用 UUID；可空，历史事件不回填。用于按应用隔离共享设备观察聚合。''', v_schema);
        EXECUTE format('COMMENT ON COLUMN %I.api_runtime_events.trace_id IS ''W3C trace_id：32 位小写 hex 且非全零；可空，历史事件不回填。仅用于同链路事件关联。''', v_schema);
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM pg_constraint con
        JOIN pg_class src ON src.oid = con.conrelid
        JOIN pg_namespace sn ON sn.oid = src.relnamespace
        JOIN pg_class dst ON dst.oid = con.confrelid
        JOIN pg_namespace dn ON dn.oid = dst.relnamespace
        WHERE con.contype = 'f'
          AND sn.nspname = v_schema AND src.relname = 'api_authz_candidate_event_receipts'
          AND dn.nspname = v_schema AND dst.relname = 'api_runtime_events'
    ) INTO v_has_fk;

    IF NOT v_has_fk THEN
        EXECUTE format(
            'DELETE FROM %I.api_authz_candidate_event_receipts r WHERE NOT EXISTS (SELECT 1 FROM %I.api_runtime_events e WHERE e.id = r.event_id)',
            v_schema, v_schema
        );
        EXECUTE format(
            'ALTER TABLE %I.api_authz_candidate_event_receipts ADD CONSTRAINT api_authz_candidate_event_receipts_event_id_fkey FOREIGN KEY (event_id) REFERENCES %I.api_runtime_events(id) ON DELETE CASCADE',
            v_schema, v_schema
        );
    END IF;

    -- ==================== 9. security_event_matches ====================
    SELECT c.relkind INTO v_relkind
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = v_schema AND c.relname = 'security_event_matches';

    IF v_relkind = 'p' THEN
        EXECUTE format('LOCK TABLE %I.security_event_matches IN ACCESS EXCLUSIVE MODE', v_schema);
        EXECUTE format($sql$
            CREATE TABLE %I._m244_u_security_event_matches (
                id                  UUID         NOT NULL DEFAULT gen_random_uuid(),
                event_id            UUID         NOT NULL,
                event_occurred_at   TIMESTAMPTZ  NOT NULL,
                rule_id             INTEGER      NOT NULL,
                rule_name           VARCHAR(512) NOT NULL DEFAULT '',
                rule_source         VARCHAR(32)  NOT NULL DEFAULT 'OWASP_CRS',
                rule_version        VARCHAR(32)  NOT NULL DEFAULT '',
                severity            VARCHAR(32)  NOT NULL DEFAULT 'NOTICE',
                message             TEXT         NOT NULL DEFAULT '',
                matched_variable    VARCHAR(255) NOT NULL DEFAULT '',
                matched_data_masked TEXT         NOT NULL DEFAULT '',
                tags                JSONB        NOT NULL DEFAULT '[]',
                phase               INTEGER      NOT NULL DEFAULT 2,
                anomaly_score       INTEGER      NOT NULL DEFAULT 0,
                created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
                CONSTRAINT _m244_old_security_event_matches_pkey PRIMARY KEY (id)
            )
        $sql$, v_schema);

        v_cols := 'id, event_id, event_occurred_at, rule_id, rule_name, rule_source, rule_version, severity, message, matched_variable, matched_data_masked, tags, phase, anomaly_score, created_at';

        EXECUTE format('SELECT count(*) FROM %I.security_event_matches', v_schema) INTO v_src_cnt;
        EXECUTE format('INSERT INTO %I._m244_u_security_event_matches (%s) SELECT %s FROM %I.security_event_matches', v_schema, v_cols, v_cols, v_schema);
        GET DIAGNOSTICS v_dst_cnt = ROW_COUNT;
        IF v_src_cnt <> v_dst_cnt THEN
            RAISE EXCEPTION 'rollback row count mismatch on security_event_matches: src %, dst %', v_src_cnt, v_dst_cnt;
        END IF;

        EXECUTE format('DROP TABLE %I.security_event_matches', v_schema);
        EXECUTE format('ALTER TABLE %I._m244_u_security_event_matches RENAME TO security_event_matches', v_schema);
        EXECUTE format('ALTER TABLE %I.security_event_matches RENAME CONSTRAINT _m244_old_security_event_matches_pkey TO security_event_matches_pkey', v_schema);

        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_event_matches_event ON %I.security_event_matches (event_id)', v_schema);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_event_matches_rule ON %I.security_event_matches (rule_id)', v_schema);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_security_event_matches_effect_stats ON %I.security_event_matches (event_occurred_at DESC, rule_id, rule_version, event_id)', v_schema);
    END IF;

    -- ==================== 10. identity_behavior_events ====================
    SELECT c.relkind INTO v_relkind
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = v_schema AND c.relname = 'identity_behavior_events';

    IF v_relkind = 'p' THEN
        EXECUTE format('LOCK TABLE %I.identity_behavior_events IN ACCESS EXCLUSIVE MODE', v_schema);
        EXECUTE format($sql$
            CREATE TABLE %I._m244_u_identity_behavior_events (
                id                  UUID         NOT NULL DEFAULT gen_random_uuid(),
                identity_id         UUID,
                identity_key        VARCHAR(128) NOT NULL,
                occurred_at         TIMESTAMPTZ  NOT NULL,
                event_kind          VARCHAR(32)  NOT NULL DEFAULT 'RECON_SIGNAL',
                rule_code           VARCHAR(64)  NOT NULL,
                rule_version        VARCHAR(32)  NOT NULL,
                signal              VARCHAR(64)  NOT NULL,
                risk_score_delta    INT          NOT NULL DEFAULT 0,
                mode                VARCHAR(16)  NOT NULL DEFAULT 'OBSERVE',
                reason              TEXT         DEFAULT '',
                metadata            JSONB        NOT NULL DEFAULT '{}'::jsonb,
                request_id          VARCHAR(128) DEFAULT '',
                client_ip           VARCHAR(64)  DEFAULT '',
                method              VARCHAR(16)  DEFAULT '',
                path                TEXT         DEFAULT '',
                app_id              VARCHAR(64)  DEFAULT '',
                domain              VARCHAR(255) DEFAULT '',
                gateway_node        VARCHAR(128) DEFAULT '',
                created_at          TIMESTAMPTZ  DEFAULT now(),
                identity_confidence SMALLINT     NOT NULL DEFAULT 0
                                    CONSTRAINT identity_behavior_events_identity_confidence_check
                                    CHECK (identity_confidence BETWEEN 0 AND 100),
                identity_evidence   JSONB        NOT NULL DEFAULT '[]'::jsonb,
                CONSTRAINT _m244_old_identity_behavior_events_pkey PRIMARY KEY (id),
                CONSTRAINT identity_behavior_events_identity_id_fkey FOREIGN KEY (identity_id) REFERENCES %I.client_identity(id) ON DELETE SET NULL
            )
        $sql$, v_schema, v_schema);

        v_cols := 'id, identity_id, identity_key, occurred_at, event_kind, rule_code, rule_version, signal, risk_score_delta, mode, reason, metadata, request_id, client_ip, method, path, app_id, domain, gateway_node, created_at, identity_confidence, identity_evidence';

        EXECUTE format('SELECT count(*) FROM %I.identity_behavior_events', v_schema) INTO v_src_cnt;
        EXECUTE format('INSERT INTO %I._m244_u_identity_behavior_events (%s) SELECT %s FROM %I.identity_behavior_events', v_schema, v_cols, v_cols, v_schema);
        GET DIAGNOSTICS v_dst_cnt = ROW_COUNT;
        IF v_src_cnt <> v_dst_cnt THEN
            RAISE EXCEPTION 'rollback row count mismatch on identity_behavior_events: src %, dst %', v_src_cnt, v_dst_cnt;
        END IF;

        EXECUTE format('DROP TABLE %I.identity_behavior_events', v_schema);
        EXECUTE format('ALTER TABLE %I._m244_u_identity_behavior_events RENAME TO identity_behavior_events', v_schema);
        EXECUTE format('ALTER TABLE %I.identity_behavior_events RENAME CONSTRAINT _m244_old_identity_behavior_events_pkey TO identity_behavior_events_pkey', v_schema);

        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_identity_behavior_events_identity ON %I.identity_behavior_events (identity_id, occurred_at DESC)', v_schema);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_identity_behavior_events_occurred ON %I.identity_behavior_events (occurred_at DESC)', v_schema);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_identity_behavior_events_signal ON %I.identity_behavior_events (signal)', v_schema);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_identity_behavior_events_request_id ON %I.identity_behavior_events (request_id, occurred_at DESC) WHERE request_id IS NOT NULL AND request_id <> ''''', v_schema);
    END IF;

    -- ==================== 11. coverage_observations ====================
    SELECT c.relkind INTO v_relkind
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = v_schema AND c.relname = 'coverage_observations';

    IF v_relkind = 'p' THEN
        EXECUTE format('LOCK TABLE %I.coverage_observations IN ACCESS EXCLUSIVE MODE', v_schema);
        EXECUTE format($sql$
            CREATE TABLE %I._m244_u_coverage_observations (
                id              UUID         NOT NULL DEFAULT gen_random_uuid(),
                request_id      VARCHAR(64)  NOT NULL,
                application_id  VARCHAR(64)  NOT NULL DEFAULT '',
                endpoint_key    VARCHAR(560) NOT NULL DEFAULT '',
                detector        VARCHAR(96)  NOT NULL,
                phase           VARCHAR(16)  NOT NULL,
                status          VARCHAR(16)  NOT NULL,
                reason_code     VARCHAR(48)  NOT NULL DEFAULT '',
                na_rule_id      VARCHAR(96)  NOT NULL DEFAULT '',
                scope_bytes     BIGINT       NOT NULL DEFAULT 0,
                scope_messages  INT          NOT NULL DEFAULT 0,
                scope_direction VARCHAR(16)  NOT NULL DEFAULT '',
                bytes_examined  BIGINT       NOT NULL DEFAULT 0,
                truncated       BOOLEAN      NOT NULL DEFAULT false,
                policy_version  VARCHAR(64)  NOT NULL DEFAULT '',
                node_id         VARCHAR(96)  NOT NULL DEFAULT '',
                occurred_at     TIMESTAMPTZ  NOT NULL,
                ingested_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
                CONSTRAINT _m244_old_coverage_observations_pkey PRIMARY KEY (id)
            )
        $sql$, v_schema);

        v_cols := 'id, request_id, application_id, endpoint_key, detector, phase, status, reason_code, na_rule_id, scope_bytes, scope_messages, scope_direction, bytes_examined, truncated, policy_version, node_id, occurred_at, ingested_at';

        EXECUTE format('SELECT count(*) FROM %I.coverage_observations', v_schema) INTO v_src_cnt;
        EXECUTE format('INSERT INTO %I._m244_u_coverage_observations (%s) SELECT %s FROM %I.coverage_observations', v_schema, v_cols, v_cols, v_schema);
        GET DIAGNOSTICS v_dst_cnt = ROW_COUNT;
        IF v_src_cnt <> v_dst_cnt THEN
            RAISE EXCEPTION 'rollback row count mismatch on coverage_observations: src %, dst %', v_src_cnt, v_dst_cnt;
        END IF;

        EXECUTE format('DROP TABLE %I.coverage_observations', v_schema);
        EXECUTE format('ALTER TABLE %I._m244_u_coverage_observations RENAME TO coverage_observations', v_schema);
        EXECUTE format('ALTER TABLE %I.coverage_observations RENAME CONSTRAINT _m244_old_coverage_observations_pkey TO coverage_observations_pkey', v_schema);

        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_coverage_obs_app_time ON %I.coverage_observations (application_id, occurred_at DESC)', v_schema);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_coverage_obs_detector_status_time ON %I.coverage_observations (detector, status, occurred_at DESC)', v_schema);
        EXECUTE format('COMMENT ON TABLE %I.coverage_observations IS ''执行覆盖观测请求级明细（NG-COV-01）：网关 JSONL 摄入，确定性 1/N 采样留存；永不进入攻击评分链路''', v_schema);
    END IF;
END $$;

DROP FUNCTION IF EXISTS uuid_generate_v7();
