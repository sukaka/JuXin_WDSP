# 九章管理控制台 · 前端 UI / CSS 样式规范

> 用途：把本仓库 **WAF / WDSP 管理面** 的视觉与布局约定沉淀下来，供其他产品线（如 **API 扫描系统**）复用同一套观感，避免「GPT 随手生成」的花哨、拥挤、多主题混搭页面。
> 实现仓库：`web/`（React 18 + Vite + **Ant Design 5/6** + Ant Design Icons）。
> 原则：**几乎不写自定义 CSS**，靠 Ant Design 主题 Token + 固定页面骨架 + 语义色标签映射。

---

## 1. 一句话设计方向

**企业安全运营控制台**：冷静、克制、信息密度适中、中文优先、状态用彩色 Tag、列表为主、操作链路清晰。

| 要 | 不要 |
|----|------|
| 单一主色 + 中性灰背景 | 渐变按钮 / 霓虹色 / 多套主题混用 |
| Card 包一层内容 | 全屏白底无分区 |
| Table + 筛选条标准列表页 | 卡片瀑布流堆操作按钮 |
| 状态枚举 → 中文 Tag | 直接渲染 `SUCCESS` / `ENABLED` |
| 侧栏深色 + 顶栏白底 | 全白侧栏或炫彩侧栏 |
| 行内 `type="link"` 操作 | 每行一堆 primary 大按钮 |

---

## 2. 技术栈（必须对齐）

```text
React 18
Vite
antd ^5 或 ^6（本仓为 antd 6.x）
@ant-design/icons
@tanstack/react-query（数据，不负责样式）
中文 locale：antd/locale/zh_CN
```

- **不要**再叠 Tailwind / Bootstrap / MUI 第二套组件库。
- **不要**为每个页面写独立 `.scss` 皮肤。
- 局部样式优先 **内联 `style={{}}`**（布局尺寸、间距），全局只保留 reset。

---

## 3. 全局 CSS（完整可复制）

本仓仅 `web/src/index.css`，全文如下：

```css
html,
body,
#root {
  margin: 0;
  padding: 0;
  height: 100%;
}

body {
  font-family:
    -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'PingFang SC',
    'Hiragino Sans GB', 'Microsoft YaHei', sans-serif;
  background: #f5f6fa;
}
```

要点：

- 页面背景 **`#f5f6fa`**（浅灰蓝，不是纯白 `#fff`，也不是深色仪表盘）。
- 中文字体优先苹方 / 微软雅黑。
- 高度链 `html/body/#root = 100%`，配合 `Layout minHeight: 100vh`。

---

## 4. 主题 Token（ConfigProvider）

本仓 `web/src/App.tsx`：

```tsx
import { ConfigProvider, App as AntdApp } from 'antd'
import zhCN from 'antd/locale/zh_CN'

<ConfigProvider
  locale={zhCN}
  theme={{
    token: {
      colorPrimary: '#2f54eb', // 极客蓝 / Geek Blue
      // 建议在新项目显式补全（本仓部分依赖 antd 默认值）：
      borderRadius: 6,
      colorBgLayout: '#f5f6fa',
      colorText: 'rgba(0, 0, 0, 0.88)',
      colorTextSecondary: 'rgba(0, 0, 0, 0.45)',
      colorBorder: '#d9d9d9',
      colorBorderSecondary: '#f0f0f0',
      fontFamily:
        "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'PingFang SC', 'Hiragino Sans GB', 'Microsoft YaHei', sans-serif",
    },
    components: {
      Layout: {
        headerBg: '#ffffff',
        bodyBg: '#f5f6fa',
        siderBg: '#001529', // antd dark sider 默认近似
      },
      Menu: {
        darkItemBg: 'transparent',
      },
      Table: {
        headerBg: '#fafafa',
      },
      Card: {
        paddingLG: 24,
      },
    },
  }}
>
  <AntdApp>{/* 必须包一层，才能用 message / modal / notification 静态方法的 context 版 */}</AntdApp>
</ConfigProvider>
```

### 4.1 主色与中性色

| Token / 用途 | 色值 | 说明 |
|--------------|------|------|
| 主色 `colorPrimary` | `#2f54eb` | 主按钮、链接、选中态、登录图标 |
| 布局背景 | `#f5f6fa` | body / Content 背后 |
| 顶栏 / 卡片底 | `#ffffff` | Header、Card |
| 分割线 | `#f0f0f0` | Header 底边、表头分隔 |
| 边框 | `#d9d9d9` | 输入框、验证码图框 |
| 次要文字 | `#888` / `rgba(0,0,0,0.45)` | 副标题、说明 |
| 侧栏文字 | `#fff` | 深色 Sider Logo |

### 4.2 语义色（Tag / 状态，用 antd Tag color 名）

列表状态 **禁止** 自己瞎配 hex，优先用 antd 内置色名：

| 语义 | Tag `color` | 中文示例 |
|------|-------------|----------|
| 成功 / 启用 / 已发布 | `green` / `success` | 成功、已启用、正常 |
| 处理中 | `processing` / `blue` | 进行中、观察 |
| 警告 / 中风险 | `orange` / `gold` | 中、即将到期 |
| 危险 / 阻断 / 高危 | `red` / `error` / `volcano` / `magenta` | 阻断、高、失败 |
| 信息 / 中性 | `default` / `cyan` / `geekblue` / `purple` | 信息、其他 |
| 严重（规则 CRITICAL） | 可用 hex `#7f1d1d` | 严重 |

本仓约定见 `web/src/utils/stage3.ts`～`stage6.ts`、`utils/ai.ts` 的 `*_META` 映射。

---

## 5. 布局骨架（Admin 壳）

参考 `web/src/layouts/AdminLayout.tsx`。

```
┌──────────┬─────────────────────────────────────┐
│  Sider   │  Header（白底 + 面包屑 + 用户）      │
│  深色    ├─────────────────────────────────────┤
│  可折叠  │  Content  margin:16                 │
│  200px   │  ┌─────────────────────────────┐    │
│          │  │ Card  title / extra         │    │
│          │  │ 筛选条 / Table / 分页       │    │
│          │  └─────────────────────────────┘    │
└──────────┴─────────────────────────────────────┘
```

### 5.1 尺寸约定

| 区域 | 值 |
|------|-----|
| 整体 | `Layout style={{ minHeight: '100vh' }}` |
| 侧栏 | `Sider collapsible theme="dark"`，展开约 200px（antd 默认） |
| Logo 区高度 | `56px`，字重 600，字号 16（折叠 14） |
| 顶栏 | `background #fff`，`padding: 0 24px`，底边 `1px solid #f0f0f0` |
| 内容区 | `Content style={{ margin: 16 }}` |
| 卡片内筛选与表格间距 | 筛选 `marginBottom: 16` |

### 5.2 侧栏

- **主题固定 dark**，不要 light sider。
- Logo 文案简短（本仓折叠后只留图标）：如「九章智能防护」。
- 菜单 `mode="inline"`，图标用 `@ant-design/icons`，一级分组用 antd SubMenu（本仓按 `group` 聚合）。
- **默认分组收起**，进入路由时再展开当前组（避免一屏菜单爆炸）。

### 5.3 顶栏

- 左：面包屑 `系统名 / 当前菜单`。
- 右：`Avatar` + 显示名 + `Dropdown`（个人资料 / 改密 / 退出）。
- 不要在顶栏堆一排功能按钮。

---

## 6. 登录页

参考 `web/src/pages/login/LoginPage.tsx`。

| 项 | 值 |
|----|-----|
| 背景 | `linear-gradient(135deg, #0f2027 0%, #203a43 50%, #2c5364 100%)` |
| 居中 | flex + `minHeight: 100vh` + `padding: 24` |
| 卡片宽度 | `400` |
| 阴影 | `boxShadow: '0 8px 32px rgba(0,0,0,0.35)'` |
| 图标 | `SafetyCertificateOutlined`，`fontSize: 40`，`color: #2f54eb` |
| 标题 | 20px / fontWeight 600 |
| 副标题 | `#888`，版本 +「管理控制台」 |
| 表单 | `size="large"`，主按钮 `type="primary" block` |
| 页脚支持信息 | `rgba(255,255,255,0.65)`，字号 13 |

---

## 7. 标准业务列表页（核心模板）

这是本系统「好看且一致」的关键，**API 扫描系统 80% 页面应照抄此结构**。

```tsx
import { Button, Card, Input, Select, Space, Table } from 'antd'
import { PlusOutlined } from '@ant-design/icons'
import StatusTag from '@/components/StatusTag'

export default function XxxListPage() {
  return (
    <Card
      title="资源名称" // 中文，不要英文 Title Case
      extra={
        <Button type="primary" icon={<PlusOutlined />}>
          新建
        </Button>
      }
    >
      {/* 1. 筛选条：一行 Space wrap，控件固定宽度 */}
      <Space style={{ marginBottom: 16 }} wrap>
        <Input.Search placeholder="关键词" allowClear style={{ width: 220 }} />
        <Select placeholder="状态" allowClear style={{ width: 140 }} options={...} />
        <Select placeholder="类型" allowClear style={{ width: 160 }} options={...} />
      </Space>

      {/* 2. 表格：小尺寸操作、固定右侧操作列 */}
      <Table
        rowKey="id"
        size="middle" // 或 small；不要 default 过大行高再叠自定义 padding
        loading={loading}
        columns={columns}
        dataSource={items}
        scroll={{ x: 1200 }} // 列多时横向滚动，避免挤压
        pagination={{
          current: page,
          pageSize,
          total,
          showSizeChanger: true,
          showTotal: (t) => `共 ${t} 条`,
        }}
      />
    </Card>
  )
}
```

### 7.1 表格列习惯

| 列类型 | 约定 |
|--------|------|
| 时间 | 宽约 165～170，格式化 `YYYY-MM-DD HH:mm:ss` |
| IP / 短 ID | 固定宽，等宽字体可选 |
| 路径 / URL | `ellipsis` + `Tooltip`，`fontFamily: monospace; fontSize: 12` |
| 状态 / 类型 / 级别 | **必须** `StatusTag` + META 映射中文 |
| 操作列 | `fixed: 'right'`，`Button type="link" size="small"`，超过 3 个进「更多」Dropdown |
| 空值 | 显示 `-`，不要空白 |

### 7.2 操作按钮层级

1. **页面级主操作**：Card `extra` 里一个 `type="primary"`（新建）。
2. **行内次要操作**：`type="link" size="small"`（编辑、详情、测试）。
3. **危险操作**：`danger` + `Popconfirm` / `Modal.confirm`。
4. **同一行禁止** 多个 `type="primary"`。

### 7.3 筛选条

- `Space wrap` + 控件 `width` 固定（140～220）。
- 变更筛选时 **重置 page=1**。
- 时间用 `DatePicker.RangePicker`，提交 ISO 字符串。

### 7.4 详情

- 列表 → `Drawer` 或独立详情路由；字段用 `Descriptions`。
- 长 JSON / 配置用 `Typography.Paragraph` + `code` 或只读 `Input.TextArea`。

---

## 8. 状态标签组件（必复用）

### 8.1 StatusTag

```tsx
// 与本仓 web/src/components/StatusTag.tsx 一致
import { Tag } from 'antd'

export default function StatusTag({
  value,
  map,
}: {
  value: string
  map: Record<string, { color: string; label: string }>
}) {
  if (!value) return <Tag>-</Tag>
  const item = map[value]
  if (!item) return <Tag>{value}</Tag> // 未知码降级；上线前应补映射
  return <Tag color={item.color}>{item.label}</Tag>
}
```

### 8.2 META 映射模板（API 扫描可直接抄）

```ts
// utils/statusMeta.ts
export const SCAN_STATUS_META: Record<string, { color: string; label: string }> = {
  PENDING: { color: 'default', label: '排队中' },
  RUNNING: { color: 'processing', label: '扫描中' },
  SUCCESS: { color: 'success', label: '成功' },
  FAILED: { color: 'error', label: '失败' },
  CANCELLED: { color: 'default', label: '已取消' },
}

export const RISK_META: Record<string, { color: string; label: string }> = {
  CRITICAL: { color: 'magenta', label: '严重' },
  HIGH: { color: 'red', label: '高' },
  MEDIUM: { color: 'orange', label: '中' },
  LOW: { color: 'blue', label: '低' },
  INFO: { color: 'default', label: '信息' },
}

export const ENABLE_STATUS_META: Record<string, { color: string; label: string }> = {
  ENABLED: { color: 'green', label: '启用' },
  DISABLED: { color: 'default', label: '停用' },
}
```

**铁律**：Table 里不要写 `<Tag>{record.status}</Tag>` 直接吐英文枚举。

---

## 9. 仪表盘 / 统计页

参考安全总览、统计分析：

- 外层 `Row` / `Col` + `Card size="small"` + `Statistic`。
- 栅格间距 `gutter={[16, 16]}`。
- 图表：ECharts，容器固定高度（如 280～360），配色跟主色 `#2f54eb` 与 antd 色板，**不要**彩虹默认 12 色乱飞。
- 排行用小号 `Table size="small" pagination={false}`。

---

## 10. 文案与中文化

| 规则 | 示例 |
|------|------|
| 菜单、Card 标题、列名全中文 | 「接口端点资产」不是 `API Endpoints` |
| 按钮动词中文 | 新建 / 编辑 / 删除 / 发布 / 确认 |
| 状态中文 | 成功 / 失败 / 启用 |
| 协议字面量可保留 | `GET` `POST` `HTTP` |
| 占位符可带示例 | `placeholder="如 10.0.0.0/8"` |
| 说明用 `Typography.Paragraph type="secondary"` | 灰字辅助，勿大段英文 |

---

## 11. 间距与字号速查

| 场景 | 值 |
|------|-----|
| 页面 Content 外边距 | 16 |
| Card 默认内边距 | antd 默认（约 24） |
| 筛选条与表格 | `marginBottom: 16` |
| 纵向多 Card | `Space direction="vertical" size={16}` 或 `display:flex; gap:16` |
| 正文 | antd 默认 14 |
| 辅助说明 | 12～13，`type="secondary"` |
| 等宽路径 | 12 monospace |
| Logo | 16 / 600 |
| 登录标题 | 20 / 600 |

圆角：跟随 token `borderRadius: 6`（按钮、输入、卡片统一）。

---

## 12. 给「API 扫描系统」的落地清单

新建前端时按顺序做：

1. **脚手架**：Vite + React 18 + antd + icons + react-router + tanstack-query。
2. **复制** 第 3 节 `index.css` + 第 4 节 `ConfigProvider`（主色 `#2f54eb`）。
3. **复制** AdminLayout 结构（深色 Sider + 白 Header + margin 16 Content）。
4. **实现** `StatusTag` + 各业务 `*_META`（扫描状态、风险等级、资产类型）。
5. **所有列表页** 用第 7 节 Card 模板；禁止 GPT 默认的「左侧彩色大图标卡片墙」。
6. **统一中文** 菜单与列名；枚举展示走 META。
7. **权限**：按钮按权限显隐，无权限不露「假按钮」。
8. **反馈**：成功/失败用 `App.useApp().message`，删除用 `modal.confirm`。
9. **不要**：全站 dark mode、毛玻璃、3D、过多动画、每页自定义主题色。

### 12.1 推荐目录（对齐本仓）

```text
src/
  App.tsx              # ConfigProvider + AntdApp
  index.css            # 仅 reset + 背景
  layouts/AdminLayout.tsx
  components/StatusTag.tsx
  utils/*Meta.ts       # 状态中文映射
  pages/<domain>/XxxPage.tsx
```

### 12.2 反模式（GPT 常见丑点 → 怎么改）

| 丑点 | 改法 |
|------|------|
| 每页一种主色 | 全局唯一 `colorPrimary` |
| 大圆角 16px + 重阴影 | `borderRadius: 6`，阴影仅登录卡 |
| 表格无 Card | 一律 Card 包裹 |
| 操作列 primary 按钮 | 改为 link |
| 状态英文枚举 | META + StatusTag |
| 侧栏浅色挤一屏图标 | 深色 Sider + 分组折叠 |
| 自定义 CSS 覆盖 antd | 优先改 theme token |
| 空状态花哨插画 | antd `Empty` 即可 |

---

## 13. 本仓库对照索引

| 内容 | 路径 |
|------|------|
| 主题入口 | `web/src/App.tsx` |
| 全局 CSS | `web/src/index.css` |
| 管理壳布局 | `web/src/layouts/AdminLayout.tsx` |
| 登录视觉 | `web/src/pages/login/LoginPage.tsx` |
| 状态 Tag | `web/src/components/StatusTag.tsx` |
| 列表页范例 | `web/src/pages/applications/ApplicationsPage.tsx`、`security-events/SecurityEventsPage.tsx`、`users/UsersPage.tsx` |
| 语义色映射 | `web/src/utils/stage3.ts`～`stage6.ts`、`utils/ai.ts` |
| 产品名常量 | `web/src/constants.ts` |

---

## 14. 可直接粘贴的最小 Theme 包（API 扫描）

```tsx
// theme.ts
import type { ThemeConfig } from 'antd'

export const appTheme: ThemeConfig = {
  token: {
    colorPrimary: '#2f54eb',
    borderRadius: 6,
    colorBgLayout: '#f5f6fa',
    fontFamily:
      "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'PingFang SC', 'Hiragino Sans GB', 'Microsoft YaHei', sans-serif",
  },
  components: {
    Layout: {
      headerBg: '#ffffff',
      bodyBg: '#f5f6fa',
    },
    Table: {
      headerBg: '#fafafa',
    },
  },
}

export const PAGE_BG = '#f5f6fa'
export const HEADER_BORDER = '#f0f0f0'
export const LOGIN_GRADIENT =
  'linear-gradient(135deg, #0f2027 0%, #203a43 50%, #2c5364 100%)'
```

---

## 15. 验收自检（视觉）

- [ ] 全站只有一个主色蓝，按钮不花
- [ ] 内容区背景发灰，卡片发白，层次清楚
- [ ] 列表：筛选一行 → 表格 → 底部分页
- [ ] 状态全是中文彩色 Tag
- [ ] 操作列是文字链，不是一排实心按钮
- [ ] 侧栏深色、顶栏白、无多余装饰线
- [ ] 中文 UI，无 GPT 式英文 Title Case 菜单

---

Copyright © 聚信得仁
All Rights Reserved.
