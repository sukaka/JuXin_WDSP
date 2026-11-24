import {
  Alert,
  Button,
  Card,
  Descriptions,
  Divider,
  Space,
  Steps,
  Tag,
  Typography,
} from 'antd'
import { ArrowRightOutlined, BookOutlined } from '@ant-design/icons'

const { Title, Paragraph, Text } = Typography

export default function RiskPolicyGuidePage() {
  return (
    <div
      style={{
        minHeight: '100vh',
        background: '#f5f7fa',
        padding: '32px 16px 64px',
      }}
    >
      <div style={{ maxWidth: 960, margin: '0 auto' }}>
        <Card>
          <Space direction="vertical" size={16} style={{ width: '100%' }}>
            <Space
              style={{
                width: '100%',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
              }}
              align="center"
            >
              <Space align="center">
                <BookOutlined style={{ fontSize: 22, color: '#1677ff' }} />
                <Title level={3} style={{ margin: 0 }}>
                  风险策略使用说明
                </Title>
                <Tag color="orange">累计扣分 · 分档处置</Tag>
              </Space>
              <Button
                type="link"
                href="/behavior-policy/guide"
                target="_blank"
                rel="noopener noreferrer"
                icon={<ArrowRightOutlined />}
                iconPosition="end"
              >
                查看「行为策略」说明
              </Button>
            </Space>

            <Alert
              type="info"
              showIcon
              message="一句话理解：风险策略像「驾照扣分」，累计风险分越高，处置措施越严厉。"
              description="系统会在统计窗口内（默认 24 小时）把同一个访问者触发的行为异常、WAF 攻击命中、API 模型偏离、认证失败等信号累计成风险分。达到对应分数线时，依次触发「限速 → JS 挑战 → 直接阻断」。"
            />

            <Divider titlePlacement="start" plain>
              一、日常怎么用（3 步上手）
            </Divider>
            <Steps
              direction="vertical"
              size="small"
              current={-1}
              items={[
                {
                  title: '第一步：先开启「观察模式」试运行',
                  description:
                    '打开「启用风险策略」，防护模式保持「观察（只记录不处置）」，其余阈值和分值保持默认。先观察一段时间，在「风险身份」中确认高分身份确实是恶意流量。',
                },
                {
                  title: '第二步：确认无误报后切换为「防护模式」',
                  description:
                    '将防护模式切换为「防护（达阈限速/挑战/阻断）」并保存。此后累计分数达到限速/挑战/阻断阈值的访问者会被自动处置。',
                },
                {
                  title: '第三步：仅在个别站点有特殊需求时配置「按应用风险覆盖」',
                  description:
                    '未配置覆盖的应用默认继承全局策略。如果某个核心站点需要更严格拦截，或某个内部测试站点需要临时放宽/停用，可在页面下方单独为该应用建一条覆盖规则。',
                },
              ]}
            />

            <Divider titlePlacement="start" plain>
              二、页面配置项说明
            </Divider>

            <Title level={5} style={{ marginBottom: 4 }}>
              1. 常用配置（首屏展示）
            </Title>
            <Descriptions bordered column={1} size="small">
              <Descriptions.Item label="启用风险策略 / 防护模式">
                控制风险引擎是否生效，以及生效后是「仅观察记录」还是「真正执行限速/挑战/阻断」。
              </Descriptions.Item>
              <Descriptions.Item label="限速阈值 + 限速速率">
                分数达到限速阈值后，限制该身份每秒最多允许的请求数（超限返回 429）。
              </Descriptions.Item>
              <Descriptions.Item label="挑战阈值（0 表示关闭）">
                开启时必须满足 <Text code>限速阈值 &lt; 挑战阈值 &lt; 阻断阈值</Text>
                。达到后会对浏览器文档请求下发 JS 挑战验证是否为真人（需对应应用开启 Bot 防护）。不需要挑战时填 0 即可。
              </Descriptions.Item>
              <Descriptions.Item label="阻断阈值">
                分数达到阻断阈值后，直接拦截该身份的后续请求（返回 403）。
              </Descriptions.Item>
            </Descriptions>

            <Title level={5} style={{ marginTop: 12, marginBottom: 4 }}>
              2. 高级参数（默认折叠，一般无需修改）
            </Title>
            <Descriptions bordered column={1} size="small">
              <Descriptions.Item label="统计窗口（秒）">
                身份风险分的滑动统计时长，默认 <Text code>86400</Text> 秒（24 小时）。窗口越长，历史恶意行为的影响保留越久。
              </Descriptions.Item>
              <Descriptions.Item label="风险等级划分">
                设定多少分展示为「中风险 / 高风险 / 严重风险」。仅影响后台列表与报表的等级标签展示，不影响实际拦截动作。
              </Descriptions.Item>
              <Descriptions.Item label="信号分值（0-100）">
                定义各类安全信号（行为探测、WAF 攻击命中、API 模型偏离、API 解析异常、认证失败等）命中后各自累加多少分。
              </Descriptions.Item>
            </Descriptions>

            <Title level={5} style={{ marginTop: 12, marginBottom: 4 }}>
              3. 按应用风险覆盖（页面下方卡片）
            </Title>
            <Descriptions bordered column={1} size="small">
              <Descriptions.Item label="继承与覆盖规则">
                没有配置覆盖的应用自动使用全局策略；如果为某应用配置了覆盖并显式停用，则该应用不再继承全局处置；删除覆盖后会立刻恢复继承全局。
              </Descriptions.Item>
              <Descriptions.Item label="同设备账号观察阈值">
                应用覆盖抽屉中可配置：同一设备关联的可信账号超过阈值时产生观察信号（0 表示默认 3 个），用于发现批量养号/撞库，仅观察不直接阻断。
              </Descriptions.Item>
            </Descriptions>

            <Divider titlePlacement="start" plain>
              三、常见问题
            </Divider>
            <Space direction="vertical" size={8} style={{ width: '100%' }}>
              <Paragraph style={{ marginBottom: 4 }}>
                <Text strong>Q：行为策略和风险策略里都有「信号分值」，有什么区别？</Text>
                <br />
                A：「行为策略」只管 10 种异常行为探测信号的生成与打分；「风险策略」是总控台，除了行为信号，还汇总 WAF 攻击、API 异常、认证失败等多路信号来算总分并决定是否拦截。
              </Paragraph>
              <Paragraph style={{ marginBottom: 0 }}>
                <Text strong>Q：怎么快速验证风险策略有没有生效？</Text>
                <br />
                A：建议先开「观察模式」，在「安全风险 → 风险身份」页面查看累计风险分与命中的信号；确认命中准确后再切回「防护模式」。
              </Paragraph>
            </Space>
          </Space>
        </Card>
      </div>
    </div>
  )
}
