-- P1-01 A1 演示测试库 schema（独立 postgres 容器空数据卷首启自动执行）
-- 全部对象为合成演示数据；不复制任何客户/生产表结构。

-- 演示商品表：固定 100 行种子（与服务代码 ItemIDMin/Max 1..100 对应）
CREATE TABLE IF NOT EXISTS demo_items (
    id          integer PRIMARY KEY,
    name        text    NOT NULL,
    price_cents integer NOT NULL
);

INSERT INTO demo_items (id, name, price_cents)
SELECT g, 'demo-item-' || g, 100 + g
FROM generate_series(1, 100) AS g
ON CONFLICT (id) DO NOTHING;

-- demo_sleep_bounded：慢查询场景用的有界延迟操作（任务书 §3.1「测试库中预先定义的
-- 延迟操作」）。延迟在库内 clamp 到 [0, 3.0] 秒——调用方传更大值也不会超限，
-- 防止演示开关被误用成放大攻击入口。2.5s 请求经 clamp 后仍 >2s，恰好落在
-- 产品慢请求口径（tail_sampling slow 阈值 2000ms / CH 慢 TTL 2s）之内。
CREATE OR REPLACE FUNCTION demo_sleep_bounded(seconds numeric)
RETURNS void
LANGUAGE plpgsql
AS $func$
DECLARE
    clamped numeric;
BEGIN
    clamped := least(greatest(COALESCE(seconds, 0), 0), 3.0);
    PERFORM pg_sleep(clamped::double precision);
END
$func$;

-- demo_raise_synthetic_error：异常场景用的固定合成错误（真实 DB 错误路径，
-- SQLSTATE P0001 raise_exception；消息为固定文案，不含任何敏感值）。
CREATE OR REPLACE FUNCTION demo_raise_synthetic_error()
RETURNS void
LANGUAGE plpgsql
AS $func$
BEGIN
    RAISE EXCEPTION 'jiuzhang demo synthetic inventory failure (P1-01)';
END
$func$;
