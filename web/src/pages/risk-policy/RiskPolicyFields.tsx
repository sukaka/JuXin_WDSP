import {
  AutoComplete,
  Button,
  Col,
  Divider,
  Form,
  InputNumber,
  Row,
  Select,
  Space,
  Switch,
  Tooltip,
  Typography,
} from 'antd'
import { MinusCircleOutlined, PlusOutlined } from '@ant-design/icons'
import { SIGNAL_META } from '../../utils/identitySecurity'

const EXTRA_SIGNAL_OPTIONS = [
  { value: 'RECON', label: '侦察' },
  { value: 'WAF', label: 'WAF 攻击命中' },
  { value: 'API_SCHEMA', label: 'API 模型偏离' },
  { value: 'API_PARSER', label: 'API 解析异常' },
  { value: 'AUTHENTICATION', label: '认证失败' },
]

const SIGNAL_KEY_OPTIONS = [
  ...Object.entries(SIGNAL_META).map(([value, meta]) => ({
    value,
    label: meta.label,
  })),
  ...EXTRA_SIGNAL_OPTIONS.filter((opt) => !(opt.value in SIGNAL_META)),
]

const MODE_OPTIONS = [
  { value: 'OBSERVE', label: '观察（只记录不处置）' },
  { value: 'PROTECT', label: '防护（达阈限速/挑战/阻断）' },
]

export default function RiskPolicyFields({
  canEdit,
  showGroupControl = false,
}: {
  canEdit: boolean
  showGroupControl?: boolean
}) {
  const mode = Form.useWatch('mode')
  return (
    <>
      <Divider titlePlacement="start" plain>
        基本设置
      </Divider>
      <Row gutter={[16, 0]}>
        <Col xs={24} sm={12} md={8}>
          <Form.Item
            name="enabled"
            label="启用风险策略"
            valuePropName="checked"
          >
            <Switch checkedChildren="启用" unCheckedChildren="停用" />
          </Form.Item>
        </Col>
        <Col xs={24} sm={12} md={8}>
          <Form.Item
            name="mode"
            label="防护模式"
            extra={
              mode === 'PROTECT' ? (
                <Typography.Text type="warning">
                  将对达阈身份实断
                </Typography.Text>
              ) : undefined
            }
          >
            <Select options={MODE_OPTIONS} />
          </Form.Item>
        </Col>
      </Row>

      {showGroupControl && (
        <>
          <Divider titlePlacement="start" plain>
            业务观察规则
          </Divider>
          <Form.Item
            name="shared_device_account_limit"
            label="同设备账号观察阈值"
            extra="0 表示默认 3 个可信账号；自定义 2-1000。仅产生观察信号，不直接阻断。"
            rules={[
              {
                validator(_, value: number | undefined) {
                  if (value === 1) {
                    return Promise.reject(
                      new Error('0 表示默认 3；自定义账号数至少为 2'),
                    )
                  }
                  return Promise.resolve()
                },
              },
            ]}
          >
            <InputNumber
              min={0}
              max={1000}
              precision={0}
              style={{ width: '100%' }}
            />
          </Form.Item>
        </>
      )}

      <Divider titlePlacement="start" plain>
        处置阈值
      </Divider>
      <Row gutter={[16, 0]}>
        <Col xs={24} sm={12} md={8}>
          <Form.Item
            name="block_threshold"
            label="阻断阈值（1-100）"
            rules={[{ required: true, message: '请输入阻断阈值' }]}
          >
            <InputNumber
              min={1}
              max={100}
              precision={0}
              style={{ width: '100%' }}
            />
          </Form.Item>
        </Col>
        <Col xs={24} sm={12} md={8}>
          <Form.Item
            name="rate_limit_threshold"
            label="限速阈值（1-100）"
            dependencies={['block_threshold']}
            rules={[
              { required: true, message: '请输入限速阈值' },
              ({ getFieldValue }) => ({
                validator(_, value: number | undefined) {
                  const block = getFieldValue('block_threshold') as
                    number | undefined
                  if (
                    value === undefined ||
                    value === null ||
                    block === undefined ||
                    block === null
                  ) {
                    return Promise.resolve()
                  }
                  if (value >= block) {
                    return Promise.reject(new Error('限速阈值必须小于阻断阈值'))
                  }
                  return Promise.resolve()
                },
              }),
            ]}
          >
            <InputNumber
              min={1}
              max={100}
              precision={0}
              style={{ width: '100%' }}
            />
          </Form.Item>
        </Col>
        <Col xs={24} sm={12} md={8}>
          <Form.Item
            name="challenge_threshold"
            label="挑战阈值（0 关闭）"
            dependencies={['rate_limit_threshold', 'block_threshold']}
            extra="开启时取值 1-100，且须大于限速阈值、小于阻断阈值；依赖本应用 Bot 防护为防护模式且已配置匹配规则。只对合格的 HTTPS GET 浏览器文档导航发起 JS 挑战，挑战后仍执行后续防护。"
            rules={[
              { required: true, message: '请输入挑战阈值' },
              ({ getFieldValue }) => ({
                validator(_, value: number | undefined) {
                  if (value === undefined || value === null || value === 0) {
                    return Promise.resolve()
                  }
                  if (value < 1 || value > 100) {
                    return Promise.reject(
                      new Error('挑战阈值开启时必须为 1-100，0 表示关闭'),
                    )
                  }
                  const rateLimit = getFieldValue('rate_limit_threshold') as
                    number | undefined
                  const block = getFieldValue('block_threshold') as
                    number | undefined
                  if (
                    rateLimit === undefined ||
                    rateLimit === null ||
                    block === undefined ||
                    block === null
                  ) {
                    return Promise.resolve()
                  }
                  if (value <= rateLimit || value >= block) {
                    return Promise.reject(
                      new Error('须满足：限速阈值 < 挑战阈值 < 阻断阈值'),
                    )
                  }
                  return Promise.resolve()
                },
              }),
            ]}
          >
            <InputNumber
              min={0}
              max={100}
              precision={0}
              style={{ width: '100%' }}
            />
          </Form.Item>
        </Col>
        <Col xs={24} sm={12} md={8}>
          <Form.Item
            name="rate_limit_rps"
            label="限速速率（次/秒）"
            rules={[{ required: true, message: '请输入限速速率' }]}
          >
            <InputNumber
              min={1}
              max={100000}
              precision={0}
              style={{ width: '100%' }}
            />
          </Form.Item>
        </Col>
        <Col xs={24} sm={12} md={8}>
          <Form.Item
            name="signal_window_seconds"
            label="统计窗口（秒）"
            extra="身份风险分累计滑窗，默认 86400（24h）"
            rules={[{ required: true, message: '请输入统计窗口' }]}
          >
            <InputNumber
              min={60}
              max={604800}
              precision={0}
              style={{ width: '100%' }}
            />
          </Form.Item>
        </Col>
      </Row>

      <Divider titlePlacement="start" plain>
        风险等级划分（起始分，1-100）
      </Divider>
      <Row gutter={[16, 0]}>
        <Col xs={24} sm={12} md={8}>
          <Form.Item
            name={['risk_levels', 'medium']}
            label="中风险下限"
            rules={[{ required: true, message: '请输入中风险下限' }]}
          >
            <InputNumber
              min={1}
              max={100}
              precision={0}
              style={{ width: '100%' }}
            />
          </Form.Item>
        </Col>
        <Col xs={24} sm={12} md={8}>
          <Form.Item
            name={['risk_levels', 'high']}
            label="高风险下限"
            rules={[{ required: true, message: '请输入高风险下限' }]}
          >
            <InputNumber
              min={1}
              max={100}
              precision={0}
              style={{ width: '100%' }}
            />
          </Form.Item>
        </Col>
        <Col xs={24} sm={12} md={8}>
          <Form.Item
            name={['risk_levels', 'critical']}
            label="严重风险下限"
            rules={[{ required: true, message: '请输入严重风险下限' }]}
          >
            <InputNumber
              min={1}
              max={100}
              precision={0}
              style={{ width: '100%' }}
            />
          </Form.Item>
        </Col>
      </Row>

      <Divider titlePlacement="start" plain>
        信号分值（各信号命中加分，0-100）
      </Divider>
      <Form.List name="score_entries">
        {(fields, { add, remove }) => (
          <>
            {fields.map((field) => (
              <Space
                key={field.key}
                style={{ display: 'flex', marginBottom: 8 }}
                align="baseline"
                wrap
              >
                <Form.Item
                  name={[field.name, 'key']}
                  style={{ marginBottom: 0 }}
                  rules={[
                    { required: true, message: '请输入信号类型' },
                    {
                      pattern: /^[A-Z][A-Z0-9_]*$/,
                      message: '仅支持大写字母、数字与下划线，如 RECON',
                    },
                  ]}
                >
                  <AutoComplete
                    options={SIGNAL_KEY_OPTIONS}
                    placeholder="选择或输入信号类型"
                    style={{ width: 320 }}
                  />
                </Form.Item>
                <Form.Item
                  name={[field.name, 'value']}
                  style={{ marginBottom: 0 }}
                  rules={[{ required: true, message: '请输入分值' }]}
                >
                  <InputNumber
                    min={0}
                    max={100}
                    precision={0}
                    placeholder="分值"
                    style={{ width: 140 }}
                  />
                </Form.Item>
                {canEdit && (
                  <Tooltip title="删除此信号分值">
                    <Button
                      type="text"
                      danger
                      icon={<MinusCircleOutlined />}
                      aria-label="删除此信号分值"
                      onClick={() => remove(field.name)}
                    />
                  </Tooltip>
                )}
              </Space>
            ))}
            {canEdit && (
              <Button
                block
                type="dashed"
                icon={<PlusOutlined />}
                onClick={() => add({ value: 10 })}
              >
                添加信号
              </Button>
            )}
          </>
        )}
      </Form.List>
    </>
  )
}
