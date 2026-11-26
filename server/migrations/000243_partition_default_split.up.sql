-- 000243 安全事件与访问控制事件 DEFAULT 分区拆分并移除 *_default（阶段 3）：
--   1) PostgreSQL 16 要求父表不存在 DEFAULT 分区时才可执行 DETACH PARTITION ... CONCURRENTLY；
--   2) 按 UTC 自然月将 security_events_default 与 access_control_events_default 存量行
--      逐月安全迁移至按月分区（保留 000008 已建 access_control_events_2026_07/2026_08），
--      校验 0 行残留后删除 *_default；
--   3) 预建 [now-2m .. now+3m] UTC 按月分区（兼容 -40d 等测试窗口与当前/未来三个月写入），幂等执行。
DO $$
DECLARE
    v_schema     TEXT := current_schema();
    v_parent     TEXT;
    v_def_rel    TEXT;
    v_buf        TEXT;
    v_m_utc      TIMESTAMP;
    v_m_next_utc TIMESTAMP;
    v_m_start    TIMESTAMPTZ;
    v_m_end      TIMESTAMPTZ;
    v_part_name  TEXT;
    v_bound_from TEXT;
    v_bound_to   TEXT;
    v_moved      BIGINT;
    v_inserted   BIGINT;
    v_rem        BIGINT;
    v_now_utc    TIMESTAMP := date_trunc('month', now() AT TIME ZONE 'UTC');
    v_offset     INT;
BEGIN
    FOREACH v_parent IN ARRAY ARRAY['security_events', 'access_control_events'] LOOP
        v_def_rel := NULL;
        SELECT c.relname
        INTO v_def_rel
        FROM pg_inherits i
        JOIN pg_class c ON c.oid = i.inhrelid
        JOIN pg_class p ON p.oid = i.inhparent
        JOIN pg_namespace n ON n.oid = p.relnamespace
        WHERE n.nspname = v_schema
          AND p.relname = v_parent
          AND pg_get_expr(c.relpartbound, c.oid) = 'DEFAULT'
        LIMIT 1;

        IF v_def_rel IS NOT NULL THEN
            EXECUTE format('LOCK TABLE %I.%I IN ACCESS EXCLUSIVE MODE', v_schema, v_parent);

            v_buf := '_split_buf_' || v_parent;
            EXECUTE format('DROP TABLE IF EXISTS pg_temp.%I', v_buf);
            EXECUTE format(
                'CREATE TEMP TABLE %I (LIKE %I.%I INCLUDING DEFAULTS) ON COMMIT DROP',
                v_buf, v_schema, v_parent
            );

            FOR v_m_utc IN EXECUTE format(
                'SELECT DISTINCT date_trunc(''month'', occurred_at AT TIME ZONE ''UTC'') FROM %I.%I ORDER BY 1',
                v_schema, v_def_rel
            ) LOOP
                v_m_next_utc := v_m_utc + interval '1 month';
                v_m_start    := v_m_utc AT TIME ZONE 'UTC';
                v_m_end      := v_m_next_utc AT TIME ZONE 'UTC';
                v_part_name  := format('%s_%s', v_parent, to_char(v_m_utc, 'YYYY_MM'));
                v_bound_from := to_char(v_m_utc, 'YYYY-MM-DD') || ' 00:00:00+00';
                v_bound_to   := to_char(v_m_next_utc, 'YYYY-MM-DD') || ' 00:00:00+00';

                EXECUTE format(
                    'WITH moved AS (DELETE FROM %I.%I WHERE occurred_at >= $1 AND occurred_at < $2 RETURNING *) '
                    || 'INSERT INTO pg_temp.%I SELECT * FROM moved',
                    v_schema, v_def_rel, v_buf
                ) USING v_m_start, v_m_end;
                GET DIAGNOSTICS v_moved = ROW_COUNT;

                EXECUTE format(
                    'CREATE TABLE IF NOT EXISTS %I.%I PARTITION OF %I.%I FOR VALUES FROM (%L) TO (%L)',
                    v_schema, v_part_name, v_schema, v_parent, v_bound_from, v_bound_to
                );

                EXECUTE format(
                    'INSERT INTO %I.%I SELECT * FROM pg_temp.%I',
                    v_schema, v_parent, v_buf
                );
                GET DIAGNOSTICS v_inserted = ROW_COUNT;

                IF v_moved <> v_inserted THEN
                    RAISE EXCEPTION 'partition split row count mismatch on %.% (%): moved %, inserted %',
                        v_schema, v_parent, v_part_name, v_moved, v_inserted;
                END IF;

                EXECUTE format('TRUNCATE pg_temp.%I', v_buf);
            END LOOP;

            EXECUTE format('SELECT count(*) FROM %I.%I', v_schema, v_def_rel) INTO v_rem;
            IF v_rem <> 0 THEN
                RAISE EXCEPTION 'default partition %.% still has % rows after split',
                    v_schema, v_def_rel, v_rem;
            END IF;

            EXECUTE format('DROP TABLE %I.%I', v_schema, v_def_rel);
        END IF;

        FOR v_offset IN -2..3 LOOP
            v_m_utc      := v_now_utc + make_interval(months => v_offset);
            v_m_next_utc := v_m_utc + interval '1 month';
            v_part_name  := format('%s_%s', v_parent, to_char(v_m_utc, 'YYYY_MM'));
            v_bound_from := to_char(v_m_utc, 'YYYY-MM-DD') || ' 00:00:00+00';
            v_bound_to   := to_char(v_m_next_utc, 'YYYY-MM-DD') || ' 00:00:00+00';

            EXECUTE format(
                'CREATE TABLE IF NOT EXISTS %I.%I PARTITION OF %I.%I FOR VALUES FROM (%L) TO (%L)',
                v_schema, v_part_name, v_schema, v_parent, v_bound_from, v_bound_to
            );
        END LOOP;
    END LOOP;
END $$;
