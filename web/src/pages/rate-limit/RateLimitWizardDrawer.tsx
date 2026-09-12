import { useEffect, useState } from 'react'
import {
  Alert,
  Button,
  DatePicker,
  Descriptions,
  Drawer,
  Form,
  Input,
  InputNumber,
  Select,
  Space,
  Steps,
  Switch,
} from 'antd'
import type { ApplicationItem, RateLimitPolicyItem } from '../../types'
import {
  RATE_LIMIT_ACTION_META,
  RATE_LIMIT_DIMENSION_META,
  RATE_LIMIT_SCOPE_META,
  RATE_LIMIT_URI_MATCH_META,
} from '../../utils/stage5'
import { WIZARD_STEPS, buildSummaryItems, optionsOf, policyToFormValues } from './wizard'
import type { PolicyFormValues } from './wizard'

interface RateLimitWizardDrawerProps {
  open: boolean
  editing: RateLimitPolicyItem | null
  saving: boolean
  apps: ApplicationItem[]
  appsLoading: boolean
  onClose: () => void
  onSubmit: (values: PolicyFormValues) => void
}

/** CC 策略分步配置向导：基本范围 → 阈值与窗口 → 处置动作 → 确认摘要 */
export default function RateLimitWizardDrawer(props: RateLimitWizardDrawerProps) {
  const { open, editing, onClose } = props
  return (
    <Drawer
      title={editing ? '编辑CC策略' : '新建CC策略'}
      open={open}
      onClose={onClose}
      width={640}
      destroyOnHidden
    >
      {open && <WizardBody {...props} />}
    </Drawer>
  )
}

function WizardBody({
  editing,
  saving,
  apps,
  appsLoading,
  onClose,
  onSubmit,
}: RateLimitWizardDrawerProps) {
  const [form] = Form.useForm<PolicyFormValues>()
  const [step, setStep] = useState(0)
  const isLast = step === WIZARD_STEPS.length - 1

  useEffect(() => {
    if (editing) form.setFieldsValue(policyToFormValues(editing))
  }, [editing, form])

  const goNext = async () => {
    const fields = WIZARD_STEPS[step].fields
    if (fields.length > 0) {
      try {
        await form.validateFields(fields as string[])
      } catch {
        // 校验未通过：停留在当前步，错误信息由表单项内联展示
        return
      }
    }
    setStep((s) => s + 1)
  }

  const stepDisplay = (index: number) => ({ display: step === index ? 'block' : 'none' })

  return (
    <>
      <Steps
        current={step}
        size="small"
        style={{ marginBottom: 24 }}
        items={WIZARD_STEPS.map((s) => ({ title: s.title, description: s.description }))}
      />
      <Form<PolicyFormValues>
        form={form}
        layout="vertical"
        initialValues={{
          scope_type: 'GLOBAL',
          uri_match_type: 'ALL',
          dimension: 'CLIENT_IP',
          algorithm: 'TOKEN_BUCKET',
          requests_limit: 100,
          window_seconds: 60,
          burst_capacity: 0,
          action: 'REJECT',
          observe_only: false,
          priority: 100,
        }}
        onFinish={(values) => onSubmit(values)}
      >
        <div style={stepDisplay(0)}>
          <Form.Item
            name="name"
            label="策略名称"
            rules={[
              { required: true, message: '请输入策略名称' },
              { max: 200, message: '不超过 200 个字符' },
            ]}
          >
            <Input placeholder="如：登录 API 防爆破" />
          </Form.Item>
          <Form.Item name="description" label="描述" rules={[{ max: 500 }]}>
            <Input.TextArea rows={2} placeholder="策略用途说明（可选）" />
          </Form.Item>
          <Space.Compact block>
            <Form.Item
              name="priority"
              label="优先级（数值小者优先）"
              style={{ width: '50%', marginRight: 8 }}
              rules={[{ required: true, message: '请输入优先级' }]}
            >
              <InputNumber min={0} max={10000} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item
              name="observe_only"
              label="仅观察（不阻断）"
              style={{ width: '50%' }}
              valuePropName="checked"
            >
              <Switch checkedChildren="是" unCheckedChildren="否" />
            </Form.Item>
          </Space.Compact>
          <Form.Item name="effective_range" label="生效 / 失效时间（留空长期生效）">
            <DatePicker.RangePicker showTime style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="scope_type" label="作用范围" rules={[{ required: true }]}>
            <Select options={optionsOf(RATE_LIMIT_SCOPE_META)} />
          </Form.Item>
          <Form.Item noStyle shouldUpdate={(prev, cur) => prev.scope_type !== cur.scope_type}>
            {({ getFieldValue }) =>
              getFieldValue('scope_type') !== 'GLOBAL' && (
                <Form.Item
                  name="application_id"
                  label="目标应用"
                  rules={[{ required: true, message: '应用/路径范围必须选择应用' }]}
                >
                  <Select
                    showSearch
                    optionFilterProp="label"
                    placeholder="选择应用"
                    loading={appsLoading}
                    options={apps.map((a) => ({
                      value: a.id,
                      label: `${a.name}（${a.code}）`,
                    }))}
                  />
                </Form.Item>
              )
            }
          </Form.Item>
          <Form.Item name="uri_match_type" label="路径匹配方式" rules={[{ required: true }]}>
            <Select options={optionsOf(RATE_LIMIT_URI_MATCH_META)} />
          </Form.Item>
          <Form.Item
            noStyle
            shouldUpdate={(prev, cur) => prev.uri_match_type !== cur.uri_match_type}
          >
            {({ getFieldValue }) => {
              const mt = getFieldValue('uri_match_type')
              if (mt === 'ALL') return null
              return (
                <>
                  {mt === 'REGEX' && (
                    <Alert
                      type="warning"
                      showIcon
                      style={{ marginBottom: 16 }}
                      message="正则匹配基于 RE2 引擎（线性时间，天然防 ReDoS），不支持回溯引用与环视语法"
                    />
                  )}
                  <Form.Item
                    name="uri_pattern"
                    label="路径匹配模式"
                    rules={[
                      { required: true, message: '请填写路径匹配模式' },
                      { max: 256, message: '不超过 256 个字符' },
                      ...(mt === 'EXACT' || mt === 'PREFIX'
                        ? [{ pattern: /^\//, message: '必须以 / 开头' }]
                        : []),
                    ]}
                  >
                    <Input
                      placeholder={mt === 'REGEX' ? '^/api/v\\d+/login$' : '/api/login'}
                      autoComplete="off"
                    />
                  </Form.Item>
                </>
              )
            }}
          </Form.Item>
        </div>

        <div style={stepDisplay(1)}>
          <Form.Item name="dimension" label="统计维度" rules={[{ required: true }]}>
            <Select options={optionsOf(RATE_LIMIT_DIMENSION_META)} />
          </Form.Item>
          <Form.Item name="algorithm" label="限速算法" rules={[{ required: true }]}>
            <Select
              options={[
                { value: 'TOKEN_BUCKET', label: '令牌桶（匀速补充，允许突发）' },
                { value: 'SLIDING_WINDOW', label: '滑动窗口（双窗口加权近似）' },
              ]}
            />
          </Form.Item>
          <Space.Compact block>
            <Form.Item
              name="requests_limit"
              label="请求数阈值"
              style={{ width: '33%', marginRight: 8 }}
              rules={[{ required: true, message: '请输入请求数阈值' }]}
            >
              <InputNumber min={1} max={1000000} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item
              name="window_seconds"
              label="统计窗口（秒）"
              style={{ width: '33%', marginRight: 8 }}
              rules={[{ required: true, message: '请输入统计窗口' }]}
            >
              <InputNumber min={1} max={86400} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item name="burst_capacity" label="突发容量（0=取阈值）" style={{ width: '34%' }}>
              <InputNumber min={0} style={{ width: '100%' }} />
            </Form.Item>
          </Space.Compact>
        </div>

        <div style={stepDisplay(2)}>
          <Form.Item name="action" label="超阈值动作" rules={[{ required: true }]}>
            <Select options={optionsOf(RATE_LIMIT_ACTION_META)} />
          </Form.Item>
          <Form.Item noStyle shouldUpdate={(prev, cur) => prev.action !== cur.action}>
            {({ getFieldValue }) =>
              getFieldValue('action') === 'TEMP_BLOCK' && (
                <Form.Item
                  name="block_duration_seconds"
                  label="临时封禁时长（秒）"
                  rules={[{ required: true, message: '临时封禁必须设置封禁时长' }]}
                  extra="最短 60 秒，最长 30 天（2592000 秒）；超阈值客户端将被临时封禁"
                >
                  <InputNumber min={60} max={2592000} style={{ width: '100%' }} />
                </Form.Item>
              )
            }
          </Form.Item>
        </div>

        {isLast && (
          <>
            <Alert
              type="info"
              showIcon
              style={{ marginBottom: 16 }}
              message="请核对以下配置摘要，确认无误后提交"
            />
            <Descriptions
              column={1}
              size="small"
              bordered
              items={buildSummaryItems(form.getFieldsValue(true), (id) => {
                const app = apps.find((a) => a.id === id)
                return app ? `${app.name}（${app.code}）` : undefined
              }).map((item) => ({ key: item.label, label: item.label, children: item.value }))}
            />
          </>
        )}
      </Form>

      <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 24 }}>
        <Button onClick={onClose}>取消</Button>
        <Space>
          {step > 0 && <Button onClick={() => setStep((s) => s - 1)}>上一步</Button>}
          {!isLast && (
            <Button type="primary" onClick={goNext}>
              下一步
            </Button>
          )}
          {isLast && (
            <Button type="primary" loading={saving} onClick={() => form.submit()}>
              {editing ? '保存' : '创建'}
            </Button>
          )}
        </Space>
      </div>
    </>
  )
}
