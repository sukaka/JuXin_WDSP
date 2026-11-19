import { useEffect } from 'react'
import { Alert, App as AntdApp, Button, Drawer, Form, Input, InputNumber, Radio, Select, Space, Typography } from 'antd'
import { DeleteOutlined, PlusOutlined } from '@ant-design/icons'
import { useMutation } from '@tanstack/react-query'
import { ApiError } from '../../api/client'
import { l7RulesApi } from '../../api/l7Rules'
import {
  L7_CONDITION_OP_META,
  L7_CONDITION_TYPE_META,
  L7_DEFAULT_CONTENT_TYPE,
  L7_MAX_BODY_BYTES,
  L7_MAX_CONDITIONS,
  L7_METHOD_PRESETS,
  L7_MULTI_VALUE_TYPES,
  L7_NAMED_TYPES,
  L7_OPS_BY_TYPE,
  utf8ByteLength,
  validateL7RedirectUrl,
  type L7ConditionFormRow,
} from '../../utils/l7rules'
import { formValuesToBody, type L7RuleFormValues } from './formValues'
import type { L7ConditionType, L7RuleItem } from '../../types'

const DEFAULT_FORM_VALUES: L7RuleFormValues = {
  name: '',
  priority: 100,
  enabled: true,
  conditions: [],
  action: 'block',
  block_status: 403,
  block_message: '',
  redirect_status: 302,
  redirect_url: '',
  custom_status: 403,
  custom_content_type: L7_DEFAULT_CONTENT_TYPE,
  custom_body: '',
}

/** 单行条件：类型下拉 + 名称/运算符/取值联动输入 */
function ConditionRow({
  fieldName,
  onRemove,
}: {
  fieldName: number
  onRemove: () => void
}) {
  const form = Form.useFormInstance<L7RuleFormValues>()
  const rowType = Form.useWatch(['conditions', fieldName, 'type'], form) as L7ConditionType | undefined
  const rowOp = Form.useWatch(['conditions', fieldName, 'op'], form) as string | undefined
  const isMulti = rowType !== undefined && L7_MULTI_VALUE_TYPES.includes(rowType)
  const needName = rowType !== undefined && L7_NAMED_TYPES.includes(rowType)
  const ops = rowType ? L7_OPS_BY_TYPE[rowType] : []
  const noValue = rowOp === 'exists' || rowOp === 'not_exists'

  /** 切换类型时重置该行的运算符与取值，避免残留非法组合 */
  const onTypeChange = (t: L7ConditionType) => {
    const rows = [...(form.getFieldValue('conditions') as L7ConditionFormRow[])]
    rows[fieldName] = {
      type: t,
      op: L7_OPS_BY_TYPE[t][0],
      name: undefined,
      value: undefined,
      values: L7_MULTI_VALUE_TYPES.includes(t) ? [] : undefined,
    }
    form.setFieldValue('conditions', rows)
  }

  return (
    <Space style={{ display: 'flex', marginBottom: 8 }} align="baseline" wrap>
      <Form.Item name={[fieldName, 'type']} noStyle rules={[{ required: true, message: '选择类型' }]}>
        <Select
          style={{ width: 110 }}
          options={Object.entries(L7_CONDITION_TYPE_META).map(([value, meta]) => ({
            value,
            label: meta.label,
          }))}
          onChange={onTypeChange}
        />
      </Form.Item>
      {needName && (
        <Form.Item
          name={[fieldName, 'name']}
          noStyle
          rules={[
            { required: true, message: '名称必填' },
            { max: 128, message: '不超过 128 字符' },
          ]}
        >
          <Input style={{ width: 150 }} placeholder="名称（如 X-Env）" autoComplete="off" />
        </Form.Item>
      )}
      {!isMulti && (
        <Form.Item name={[fieldName, 'op']} noStyle rules={[{ required: true, message: '选择运算符' }]}>
          <Select
            style={{ width: 110 }}
            options={ops.map((op) => ({ value: op, label: L7_CONDITION_OP_META[op]?.label ?? op }))}
          />
        </Form.Item>
      )}
      {isMulti ? (
        <Form.Item
          name={[fieldName, 'values']}
          noStyle
          rules={[{ required: true, message: '至少一个取值' }]}
        >
          <Select
            mode="tags"
            style={{ minWidth: 260 }}
            placeholder={rowType === 'method' ? '选择或输入方法' : '输入 IP/CIDR 后回车'}
            options={rowType === 'method' ? L7_METHOD_PRESETS.map((m) => ({ value: m, label: m })) : undefined}
            open={rowType === 'method' ? undefined : false}
            suffixIcon={rowType === 'method' ? undefined : null}
          />
        </Form.Item>
      ) : (
        !noValue && (
          <Form.Item
            name={[fieldName, 'value']}
            noStyle
            rules={[
              { required: true, message: '匹配值必填' },
              { max: 512, message: '不超过 512 字符' },
            ]}
          >
            <Input
              style={{ width: 260 }}
              placeholder={rowType === 'request_body' || rowType === 'response_body' ? '输入正文关键字或正则' : '匹配值'}
              autoComplete="off"
            />
          </Form.Item>
        )
      )}
      <Button type="text" size="small" danger icon={<DeleteOutlined />} onClick={onRemove} aria-label="删除条件" />
    </Space>
  )
}

/** 自定义页面内容字节计数（64KB 上限按 UTF-8 字节计） */
function CustomBodyInput({ value, onChange }: { value?: string; onChange?: (v: string) => void }) {
  const bytes = utf8ByteLength(value ?? '')
  const over = bytes > L7_MAX_BODY_BYTES
  return (
    <div>
      <Input.TextArea
        rows={6}
        value={value}
        onChange={(e) => onChange?.(e.target.value)}
        placeholder="自定义页面内容（HTML 或纯文本）"
        style={{ fontFamily: 'monospace' }}
      />
      <Typography.Text type={over ? 'danger' : 'secondary'} style={{ fontSize: 12 }}>
        {bytes} / {L7_MAX_BODY_BYTES} 字节{over ? '（超出上限）' : ''}
      </Typography.Text>
    </div>
  )
}

export default function L7RuleFormDrawer({
  open,
  editing,
  initialValues,
  onClose,
  onSaved,
}: {
  open: boolean
  /** 编辑中的规则；新建/复制时为 null */
  editing: L7RuleItem | null
  /** 复制时传入预填值（editing 为 null） */
  initialValues?: L7RuleFormValues | null
  onClose: () => void
  onSaved: () => void
}) {
  const { message } = AntdApp.useApp()
  const [form] = Form.useForm<L7RuleFormValues>()
  const action = Form.useWatch('action', form)

  useEffect(() => {
    if (open) {
      form.setFieldsValue(initialValues ?? DEFAULT_FORM_VALUES)
    } else {
      form.resetFields()
    }
  }, [open, initialValues, form])

  const saveMutation = useMutation({
    mutationFn: (values: L7RuleFormValues) => {
      const body = formValuesToBody(values)
      return editing ? l7RulesApi.update(editing.id, body) : l7RulesApi.create(body)
    },
    onSuccess: () => {
      message.success(editing ? '规则已更新（发布后生效）' : '规则已创建（发布后生效）')
      onSaved()
    },
    onError: (e: unknown) => {
      message.error(e instanceof ApiError ? e.message : '保存失败')
    },
  })

  return (
    <Drawer
      title={editing ? `编辑规则「${editing.name}」` : '新建规则'}
      open={open}
      onClose={onClose}
      width={720}
      destroyOnHidden
      footer={
        <Space style={{ display: 'flex', justifyContent: 'flex-end' }}>
          <Button onClick={onClose}>取消</Button>
          <Button type="primary" loading={saveMutation.isPending} onClick={() => form.submit()}>
            {editing ? '保存' : '创建'}
          </Button>
        </Space>
      }
    >
      <Form<L7RuleFormValues>
        form={form}
        layout="vertical"
        initialValues={DEFAULT_FORM_VALUES}
        onFinish={(values) => saveMutation.mutate(values)}
      >
        <Space.Compact block>
          <Form.Item
            name="name"
            label="规则名称"
            style={{ width: '60%', marginRight: 8 }}
            rules={[
              { required: true, message: '请输入规则名称' },
              { max: 200, message: '不超过 200 个字符' },
            ]}
          >
            <Input placeholder="如：拦截后台路径外部访问" />
          </Form.Item>
          <Form.Item
            name="priority"
            label="优先级（数值小者优先，首中即停）"
            style={{ width: '40%' }}
            rules={[{ required: true, message: '请输入优先级' }]}
          >
            <InputNumber min={0} max={100000} style={{ width: '100%' }} />
          </Form.Item>
        </Space.Compact>
        <Form.Item name="enabled" label="启用状态" rules={[{ required: true }]}>
          <Radio.Group
            options={[
              { value: true, label: '启用' },
              { value: false, label: '停用' },
            ]}
            optionType="button"
          />
        </Form.Item>

        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 12 }}
          message="请求体在访问源站前检查；返回头、返回体在源站响应后检查。含响应条件的规则与其他请求条件仍按且（全部满足）组合，各阶段内按优先级首中即停。正文仅检查完整且不超过 1 MiB 的内容；超限、流式或无法解码时完整透传并不产生正文匹配。"
        />
        <Form.Item label={`匹配条件（多条件且（全部满足），最多 ${L7_MAX_CONDITIONS} 个；无条件匹配全部请求）`}>
          <Form.List name="conditions">
            {(fields, { add, remove }) => (
              <>
                {fields.map((field) => (
                  <ConditionRow key={field.key} fieldName={field.name} onRemove={() => remove(field.name)} />
                ))}
                <Button
                  type="dashed"
                  block
                  icon={<PlusOutlined />}
                  disabled={fields.length >= L7_MAX_CONDITIONS}
                  onClick={() => add({ type: 'uri', op: 'prefix' } satisfies L7ConditionFormRow)}
                >
                  添加条件
                </Button>
              </>
            )}
          </Form.List>
        </Form.Item>

        <Form.Item name="action" label="命中动作" rules={[{ required: true, message: '请选择动作' }]}>
          <Radio.Group
            options={[
              { value: 'block', label: '阻止' },
              { value: 'allow', label: '允许' },
              { value: 'redirect', label: '重定向' },
              { value: 'custom_page', label: '自定义页面' },
            ]}
            optionType="button"
          />
        </Form.Item>

        {action === 'block' && (
          <>
            <Form.Item
              name="block_status"
              label="响应状态码"
              rules={[{ required: true, message: '请输入状态码' }]}
            >
              <InputNumber min={100} max={599} style={{ width: 200 }} />
            </Form.Item>
            <Form.Item name="block_message" label="拦截文案" rules={[{ max: 500, message: '不超过 500 字符' }]}>
              <Input.TextArea rows={2} placeholder="返回给客户端的拦截提示文案（可选）" />
            </Form.Item>
          </>
        )}
        {action === 'allow' && (
          <Alert
            type="info"
            showIcon
            style={{ marginBottom: 16 }}
            message="命中后放行请求，并跳过 CC 频率限制等后续访问控制检查；请求仍会经过 Coraza/CRS 攻击检测（安全底线）。"
          />
        )}
        {action === 'redirect' && (
          <>
            <Form.Item name="redirect_status" label="重定向状态码" rules={[{ required: true }]}>
              <Radio.Group
                options={[
                  { value: 301, label: '301 永久重定向' },
                  { value: 302, label: '302 临时重定向' },
                ]}
                optionType="button"
              />
            </Form.Item>
            <Form.Item
              name="redirect_url"
              label="重定向 URL（仅支持 http/https）"
              rules={[
                { required: true, message: '请输入重定向 URL' },
                {
                  validator: (_, v: string) => {
                    const err = validateL7RedirectUrl(v ?? '')
                    return err ? Promise.reject(new Error(err)) : Promise.resolve()
                  },
                },
              ]}
            >
              <Input placeholder="https://example.com/moved" autoComplete="off" />
            </Form.Item>
          </>
        )}
        {action === 'custom_page' && (
          <>
            <Space.Compact block>
              <Form.Item
                name="custom_status"
                label="响应状态码"
                style={{ width: '40%', marginRight: 8 }}
                rules={[{ required: true, message: '请输入状态码' }]}
              >
                <InputNumber min={100} max={599} style={{ width: '100%' }} />
              </Form.Item>
              <Form.Item
                name="custom_content_type"
                label="Content-Type"
                style={{ width: '60%' }}
                rules={[
                  { required: true, message: '请输入 Content-Type' },
                  { max: 128, message: '不超过 128 字符' },
                ]}
              >
                <Input placeholder="text/html; charset=utf-8" autoComplete="off" />
              </Form.Item>
            </Space.Compact>
            <Form.Item
              name="custom_body"
              label="页面内容（≤ 64KB）"
              rules={[
                {
                  validator: (_, v: string) =>
                    utf8ByteLength(v ?? '') > L7_MAX_BODY_BYTES
                      ? Promise.reject(new Error('页面内容超过 64KB 上限'))
                      : Promise.resolve(),
                },
              ]}
            >
              <CustomBodyInput />
            </Form.Item>
          </>
        )}
      </Form>
    </Drawer>
  )
}
