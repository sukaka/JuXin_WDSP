-- 000243 回滚：将 000243 及运行期新增的 YYYY_MM 按月分区数据迁回 *_default，
-- 并保留 000008_stage5 既有的 access_control_events_2026_07 与 access_control_events_2026_08。
DO $$
DECLARE
    v_schema    TEXT := current_schema();
    v_parent    TEXT;
    v_def_name  TEXT;
    v_buf       TEXT;
    v_part_rel  TEXT;
    v_part_rows BIGINT;
    v_staged    BIGINT;
    v_restored  BIGINT;
BEGIN
    FOREACH v_parent IN ARRAY ARRAY['security_events', 'access_control_events'] LOOP
        EXECUTE format('LOCK TABLE %I.%I IN ACCESS EXCLUSIVE MODE', v_schema, v_parent);

        v_def_name := v_parent || '_default';
        v_buf      := '_down_buf_' || v_parent;
        v_staged   := 0;

        EXECUTE format('DROP TABLE IF EXISTS pg_temp.%I', v_buf);
        EXECUTE format(
            'CREATE TEMP TABLE %I (LIKE %I.%I INCLUDING DEFAULTS) ON COMMIT DROP',
            v_buf, v_schema, v_parent
        );

        FOR v_part_rel IN
            SELECT c.relname
            FROM pg_inherits i
            JOIN pg_class c ON c.oid = i.inhrelid
            JOIN pg_class p ON p.oid = i.inhparent
            JOIN pg_namespace n ON n.oid = p.relnamespace
            WHERE n.nspname = v_schema
              AND p.relname = v_parent
              AND pg_get_expr(c.relpartbound, c.oid) <> 'DEFAULT'
              AND c.relname ~ ('^' || v_parent || '_\d{4}_\d{2}$')
              AND NOT (
                  v_parent = 'access_control_events'
                  AND c.relname IN ('access_control_events_2026_07', 'access_control_events_2026_08')
              )
            ORDER BY c.relname
        LOOP
            EXECUTE format('INSERT INTO pg_temp.%I SELECT * FROM %I.%I', v_buf, v_schema, v_part_rel);
            GET DIAGNOSTICS v_part_rows = ROW_COUNT;
            v_staged := v_staged + v_part_rows;

            EXECUTE format('DROP TABLE %I.%I', v_schema, v_part_rel);
        END LOOP;

        IF NOT EXISTS (
            SELECT 1
            FROM pg_inherits i
            JOIN pg_class c ON c.oid = i.inhrelid
            JOIN pg_class p ON p.oid = i.inhparent
            JOIN pg_namespace n ON n.oid = p.relnamespace
            WHERE n.nspname = v_schema
              AND p.relname = v_parent
              AND pg_get_expr(c.relpartbound, c.oid) = 'DEFAULT'
        ) THEN
            EXECUTE format(
                'CREATE TABLE IF NOT EXISTS %I.%I PARTITION OF %I.%I DEFAULT',
                v_schema, v_def_name, v_schema, v_parent
            );
        END IF;

        IF v_staged > 0 THEN
            EXECUTE format('INSERT INTO %I.%I SELECT * FROM pg_temp.%I', v_schema, v_parent, v_buf);
            GET DIAGNOSTICS v_restored = ROW_COUNT;
            IF v_staged <> v_restored THEN
                RAISE EXCEPTION 'rollback restore row count mismatch on %.%: staged %, restored %',
                    v_schema, v_parent, v_staged, v_restored;
            END IF;
        END IF;
    END LOOP;
END $$;
