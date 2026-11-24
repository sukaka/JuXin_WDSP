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

export default function BehaviorPolicyGuidePage() {
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
          <Space
            direction="vertical"
            size={16}
            style={{ width: '100%' }}
          >
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
                  行为策略使用说明
                </Title>
                <Tag color="blue">仅观察打分 · 不直接阻断</Tag>
              </Space>
              <Button
                type="link"
                href="/risk-policy/guide"
                target="_blank"
                rel="noopener noreferrer"
                icon={<ArrowRightOutlined />}
                iconPosition="end"
              >
                查看「风险策略」说明
              </Button>
            </Space>

            <Alert
              type="info"
              showIcon
              message="一句话理解：行为策略是给「可疑访问动作」定打分标准的规则表。"
              description="它专门识别扫描目录、探测敏感路径、反复试探参数、撞库、遍历账号/订单等攻击前兆行为。命中后只会给该访问者累计风险分并记录事件，不会直接拦截请求；真正要限速、挑战或拦截时，由「风险策略」根据累计风险分统一执行。"
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
                  title: '第一步：打开「启用行为检测」开关，其余阈值保持默认',
                  description:
                    '系统内置的检测阈值与风险分值已按常见 Web/API 场景调优，初次启用无需逐项修改，开启后即可在「风险身份」中观察识别效果。',
                },
                {
                  title: '第二步：补充你的业务信息（敏感路径 + 白名单）',
                  description:
                    '把需要重点盯防的后台或敏感路径（如 /admin、/backup）填入「敏感路径」；把公司内网监控、健康检查、合法压测或扫描器加入「IP 白名单 / User-Agent 白名单」，避免误计分。',
                },
                {
                  title: '第三步：确认无误报后，去「风险策略」开启防护',
                  description:
                    '行为策略本身永远处于观察模式。确认风险识别准确后，前往「应用防护策略 → 风险策略」将防护模式切为「防护」，即可自动对高风险身份执行限速、JS 挑战或阻断。',
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
              <Descriptions.Item label="启用行为检测">
                总开关。开启后网关会按访问者身份统计窗口内的异常行为并生成信号。
              </Descriptions.Item>
              <Descriptions.Item label="检测模式">
                固定为「观察（仅计分记录，不阻断）」，确保不会因行为规则误伤正常业务。
              </Descriptions.Item>
              <Descriptions.Item label="敏感路径">
                填写不希望被外部随意探测的路径前缀（如 <Text code>/admin</Text>、
                <Text code>/backup</Text>）。访问者频繁触碰这些路径时，会触发「敏感路径探测」与「低慢侦察」信号。
              </Descriptions.Item>
              <Descriptions.Item label="IP / User-Agent 白名单">
                命中白名单的请求不参与行为计分。建议将监控探针、健康检查、内部测试工具加进来。
              </Descriptions.Item>
            </Descriptions>

            <Title level={5} style={{ marginTop: 12, marginBottom: 4 }}>
              2. 高级参数（默认折叠，一般无需修改）
            </Title>
            <Descriptions bordered column={1} size="small">
              <Descriptions.Item label="扫目录 / 探路阈值">
                包含 <Text strong>URI 枚举阈值</Text>、<Text strong>新 URI 比例</Text>、
                <Text strong>404 比例 / 最小请求数</Text>、<Text strong>低慢敏感路径命中数</Text>
                。用于发现目录扫描器、资产踩点和慢速爬虫。
              </Descriptions.Item>
              <Descriptions.Item label="接口试探 / 撞库阈值">
                包含 <Text strong>方法枚举阈值</Text>（反复切换 GET/POST/PUT/DELETE 等）、
                <Text strong>参数变异阈值</Text>（持续变化参数组合）、
                <Text strong>认证失败阈值</Text>（连续登录/鉴权失败）。
              </Descriptions.Item>
              <Descriptions.Item label="业务遍历阈值与标识字段">
                包含 <Text strong>账号枚举阈值</Text>、<Text strong>对象枚举阈值</Text>，以及对应的
                <Text strong>账号标识字段</Text> / <Text strong>对象标识字段</Text>（如{' '}
                <Text code>username</Text>、<Text code>order_id</Text>
                ，仅保存字段名，不保存用户实际值），用于识别批量遍历账号或越权拖库行为。
              </Descriptions.Item>
              <Descriptions.Item label="风险分值（0-100）">
                定义 10 种行为信号各自命中后加多少分。分值越高，该行为越容易把访问者推到高风险档位。
              </Descriptions.Item>
            </Descriptions>

            <Divider titlePlacement="start" plain>
              三、常见问题
            </Divider>
            <Space direction="vertical" size={8} style={{ width: '100%' }}>
              <Paragraph style={{ marginBottom: 4 }}>
                <Text strong>Q：为什么这里不能选择「拦截/阻断」？</Text>
                <br />
                A：单一行为信号（比如偶发几次 404）直接拦截容易误杀正常用户。系统采用「行为策略只打分 + 风险策略按总分处置」的分层设计，避免单点误判。
              </Paragraph>
              <Paragraph style={{ marginBottom: 0 }}>
                <Text strong>Q：误报太多怎么调？</Text>
                <br />
                A：如果是内部工具或监控触发，优先加到「白名单」；如果是真实业务流量特性导致（如正常接口本身参数变化多），再展开「高级参数」适当调高对应阈值或降低该信号分值。
              </Paragraph>
            </Space>
          </Space>
        </Card>
      </div>
    </div>
  )
}
