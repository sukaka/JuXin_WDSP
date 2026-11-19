import { useState } from 'react'
import { Alert, App as AntdApp, Button, Form, Input, Modal, Select, Space, Typography } from 'antd'
import { DeleteOutlined, ExperimentOutlined, PlusOutlined } from '@ant-design/icons'
import { useMutation } from '@tanstack/react-query'
import { ApiError } from '../../api/client'
import { l7RulesApi } from '../../api/l7Rules'
import StatusTag from '../../components/StatusTag'
import { L7_METHOD_PRESETS, L7_RULE_ACTION_META } from '../../utils/l7rules'
import { isValidIPLiteral } from '../../utils/stage5'
import type { L7RuleTestResult } from '../../types'

interface KVRow {
  name?: string
  value?: string
}

interface TesterFormValues {
  uri: string
  method: string
  client_ip: string
  headers: KVRow[]
  cookies: KVRow[]
  query: KVRow[]
  request_body?: string
  response_headers: KVRow[]
  response_body?: string
}

/** 键值对行 → Record（跳过空名称行；重名键后者覆盖前者） */
function kvRowsToRecord(rows: KVRow[] | undefined): Record<string, string> {
  const out: Record<string, string> = {}
  for (const row of rows ?? []) {
    const name = (row.name ?? '').trim()
    if (name !== '') out[name] = row.value ?? ''
  }
  return out
}

/** 键值对动态行（请求头 / Cookie / Query 参数共用） */
function KVList({ name, addText }: { name: string; addText: string }) {
  return (
    <Form.List name={name}>
      {(fields, { add, remove }) => (
        <>
          {fields.map((field) => (
            <Space key={field.key} style={{ display: 'flex', marginBottom: 8 }} align="baseline">
              <Form.Item name={[field.name, 'name']} noStyle>
                <Input style={{ width: 200 }} placeholder="名称" autoComplete="off" />
              </Form.Item>
              <Form.Item name={[field.name, 'value']} noStyle>
                <Input style={{ width: 280 }} placeholder="值" autoComplete="off" />
              </Form.Item>
              <Button
                type="text"
                size="small"
                danger
                icon={<DeleteOutlined />}
                onClick={() => remove(field.name)}
                aria-label="删除行"
              />
            </Space>
          ))}
          <Button type="dashed" size="small" icon={<PlusOutlined />} onClick={() => add({} satisfies KVRow)}>
            {addText}
          </Button>
        </>
      )}
    </Form.List>
  )
}

/** L7 规则测试器：模拟一次请求，展示命中的规则与动作（不产生真实流量、不写事件） */
export default function L7RuleTesterModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { message } = AntdApp.useApp()
  const [form] = Form.useForm<TesterFormValues>()
  const [result, setResult] = useState<L7RuleTestResult | null>(null)

  const testMutation = useMutation({
    mutationFn: (values: TesterFormValues) =>
      l7RulesApi.test({
        uri: values.uri,
        method: values.method,
        client_ip: values.client_ip,
        headers: kvRowsToRecord(values.headers),
        cookies: kvRowsToRecord(values.cookies),
        query: kvRowsToRecord(values.query),
        request_body: values.request_body ?? '',
        response_headers: kvRowsToRecord(values.response_headers),
        response_body: values.response_body ?? '',
      }),
    onSuccess: (data) => setResult(data),
    onError: (e: unknown) => {
      message.error(e instanceof ApiError ? e.message : '测试失败')
    },
  })

  return (
    <Modal
      title={
        <Space>
          <ExperimentOutlined />
          规则测试器
        </Space>
      }
      open={open}
      onCancel={() => {
        setResult(null)
        onClose()
      }}
      footer={null}
      width={680}
      destroyOnHidden
    >
      <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
        按当前已保存的规则（含未发布的草稿）模拟请求和响应内容评估：优先级升序、首中即停；测试不产生真实流量，也不写命中事件。
      </Typography.Paragraph>
      <Form<TesterFormValues>
        form={form}
        layout="vertical"
        initialValues={{ method: 'GET', uri: '/', headers: [], cookies: [], query: [], response_headers: [] }}
        onFinish={(values) => {
          setResult(null)
          testMutation.mutate(values)
        }}
      >
        <Space.Compact block>
          <Form.Item
            name="uri"
            label="请求 URI"
            style={{ width: '55%', marginRight: 8 }}
            rules={[
              { required: true, message: '请输入 URI' },
              {
                validator: (_, v: string) =>
                  typeof v === 'string' && v.startsWith('/')
                    ? Promise.resolve()
                    : Promise.reject(new Error('URI 须以 / 开头')),
              },
            ]}
          >
            <Input placeholder="/admin/login" autoComplete="off" />
          </Form.Item>
          <Form.Item name="method" label="请求方法" style={{ width: '20%', marginRight: 8 }} rules={[{ required: true }]}>
            <Select options={L7_METHOD_PRESETS.map((m) => ({ value: m, label: m }))} />
          </Form.Item>
          <Form.Item
            name="client_ip"
            label="来源 IP"
            style={{ width: '25%' }}
            rules={[
              { required: true, message: '请输入来源 IP' },
              {
                validator: (_, v: string) =>
                  isValidIPLiteral(v ?? '')
                    ? Promise.resolve()
                    : Promise.reject(new Error('IP 格式非法')),
              },
            ]}
          >
            <Input placeholder="203.0.113.66" autoComplete="off" />
          </Form.Item>
        </Space.Compact>
        <Form.Item label="请求头">
          <KVList name="headers" addText="添加请求头" />
        </Form.Item>
        <Form.Item label="Cookie">
          <KVList name="cookies" addText="添加 Cookie" />
        </Form.Item>
        <Form.Item label="Query 参数">
          <KVList name="query" addText="添加参数" />
        </Form.Item>
        <Form.Item name="request_body" label="请求体">
          <Input.TextArea rows={3} placeholder="可选，用于测试请求体关键字或正则条件" />
        </Form.Item>
        <Form.Item label="返回头">
          <KVList name="response_headers" addText="添加返回头" />
        </Form.Item>
        <Form.Item name="response_body" label="返回体">
          <Input.TextArea rows={3} placeholder="可选，用于测试返回体关键字或正则条件" />
        </Form.Item>
        <Button type="primary" htmlType="submit" loading={testMutation.isPending}>
          开始测试
        </Button>
      </Form>

      {result && (
        <Alert
          style={{ marginTop: 16 }}
          type={result.matched ? 'success' : 'info'}
          showIcon
          message={
            result.matched ? (
              <Space>
                命中规则「{result.rule_name ?? result.rule_id}」
                {result.action && <StatusTag value={result.action} map={L7_RULE_ACTION_META} />}
              </Space>
            ) : (
              '不命中任何规则，将继续后续检查'
            )
          }
          description={result.reason || undefined}
        />
      )}
    </Modal>
  )
}
