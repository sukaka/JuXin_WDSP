-- 扩展 API 用途分类，覆盖商品、履约、服务、增长、内容和平台类常见业务接口。
-- 不覆盖同编码的既有分类，允许迁移安全重放。
BEGIN;

INSERT INTO api_classifications (code, name, description, is_builtin) VALUES
    ('PRODUCT_CATALOG',       '商品目录',   '商品、服务、SKU、类目与价格管理接口', TRUE),
    ('INVENTORY_LOGISTICS',   '库存物流',   '库存、仓储、配送、运单与物流轨迹接口', TRUE),
    ('CUSTOMER_SERVICE',      '客户服务',   '客户咨询、客服会话、投诉与售后服务接口', TRUE),
    ('MARKETING_GROWTH',      '营销增长',   '营销活动、优惠权益、会员与增长运营接口', TRUE),
    ('CONTENT_COMMUNITY',     '内容社区',   '内容发布、评论互动、关注与内容审核接口', TRUE),
    ('MEDIA_STREAMING',       '音视频媒体', '音视频转码、播放、直播与点播管理接口', TRUE),
    ('LOCATION_SERVICE',      '位置服务',   '定位、地理编码、地图检索与电子围栏接口', TRUE),
    ('DEVELOPER_PLATFORM',    '开发者平台', '开放 API、应用凭证、SDK、沙箱与调用配额接口', TRUE)
ON CONFLICT (code) DO NOTHING;

COMMIT;
