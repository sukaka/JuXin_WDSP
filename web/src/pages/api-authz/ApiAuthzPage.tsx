import { useMutation } from '@tanstack/react-query'
import { App as AntdApp, Button, Card, Descriptions, Form, Input, Space, Tabs, Typography } from 'antd'
import { apiAuthzApi } from '../../api/apiAuthz'
import { ApiError } from '../../api/client'
import StatusTag from '../../components/StatusTag'
import EndpointSelect from './EndpointSelect'
import FieldPermissionsTab from './FieldPermissionsTab'
import { API_BOLA_VERDICT_META } from './meta'
import OwnershipTab from './OwnershipTab'
import ObjectAuthorizationTab from './ObjectAuthorizationTab'
import RoleBaselinesTab from './RoleBaselinesTab'

interface EvaluateFormValues {
  endpoint_id: string
  identity?: string
  object_id: string
}

/**
 * API 授权管理（WDSP / 阶段8）：可信对象关系、角色基线（BFLA）、对象权属观测与字段权限，
 * 附 BOLA 五档评估工具。各写操作按服务端定义的细粒度权限控制。
 */
export default function ApiAuthzPage() {
  const { message } = AntdApp.useApp()
  const [evalForm] = Form.useForm<EvaluateFormValues>()

  const evaluateMut = useMutation({
    mutationFn: (v: EvaluateFormValues) =>
      apiAuthzApi.evaluate({ endpoint_id: v.endpoint_id, identity: v.identity?.trim() || undefined, object_id: v.object_id.trim() }),
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '评估失败'),
  })

  const result = evaluateMut.data

  return (
    <Card title="API 授权管理">
      <Typography.Paragraph type="secondary">
        维护可信对象关系与接口级授权基线：对象授权面板用于确认 OWNER 关系并查看 OBSERVE 决策链，角色基线覆盖功能级越权（BFLA），
        对象权属观测支撑 BOLA 人工研判，字段权限约束字段级读写；评估工具按五档阶梯给出结论，不仅凭 ID 变化定罪。
      </Typography.Paragraph>

      <Card type="inner" title="BOLA 评估工具" style={{ marginBottom: 16 }}>
        <Form<EvaluateFormValues>
          form={evalForm}
          layout="inline"
          style={{ rowGap: 8 }}
          onFinish={(v) => evaluateMut.mutate(v)}
        >
          <Form.Item name="endpoint_id" label="接口" rules={[{ required: true, message: '请选择接口' }]} style={{ minWidth: 280 }}>
            <EndpointSelect placeholder="选择接口" />
          </Form.Item>
          <Form.Item name="identity" label="身份指纹" rules={[{ max: 128, message: '身份指纹不超过 128 字符' }]}>
            <Input placeholder="留空 = 匿名身份" allowClear style={{ width: 220 }} autoComplete="off" />
          </Form.Item>
          <Form.Item
            name="object_id"
            label="对象 ID"
            rules={[
              { required: true, message: '请填写对象 ID' },
              { max: 256, message: '对象 ID 不超过 256 字符' },
            ]}
          >
            <Input placeholder="如 12345" allowClear style={{ width: 200 }} autoComplete="off" />
          </Form.Item>
          <Form.Item>
            <Button type="primary" htmlType="submit" loading={evaluateMut.isPending}>
              评估
            </Button>
          </Form.Item>
        </Form>

        {result ? (
          <div style={{ marginTop: 16 }}>
            <Space size={12} wrap align="center">
              <StatusTag value={result.verdict} map={API_BOLA_VERDICT_META} />
              <Typography.Text strong type={result.allowed === false ? 'danger' : result.allowed ? 'success' : 'secondary'}>
                {result.allowed === null || result.allowed === undefined ? '无法判定' : result.allowed ? '倾向允许' : '倾向越权'}
              </Typography.Text>
              <Typography.Text type="secondary">置信度 {(result.confidence * 100).toFixed(0)}%</Typography.Text>
            </Space>
            <Typography.Paragraph style={{ marginTop: 8, marginBottom: 8 }}>{result.comment}</Typography.Paragraph>
            {result.evidence ? (
              <Descriptions size="small" column={{ xs: 2, sm: 3, md: 5 }}>
                <Descriptions.Item label="权属匹配">{result.evidence.own_match ? '是' : '否'}</Descriptions.Item>
                <Descriptions.Item label="对象属主数">{result.evidence.object_owner_count}</Descriptions.Item>
                <Descriptions.Item label="身份权属对象数">{result.evidence.identity_object_count}</Descriptions.Item>
                <Descriptions.Item label="身份历史事件数">{result.evidence.identity_event_count}</Descriptions.Item>
                <Descriptions.Item label="API 权属记录数">{result.evidence.endpoint_ownership_rows}</Descriptions.Item>
              </Descriptions>
            ) : null}
          </div>
        ) : (
          <Typography.Paragraph type="secondary" style={{ marginTop: 12, marginBottom: 0 }}>
            选择接口并填写对象 ID 后发起评估：结论分五档（策略确认 / 高置信 / 倾向 / 可疑 / 证据不足），并附证据计数供研判溯源。
          </Typography.Paragraph>
        )}
      </Card>

      <Tabs
        defaultActiveKey="baselines"
        items={[
          { key: 'object-authorization', label: '对象授权', children: <ObjectAuthorizationTab /> },
          { key: 'baselines', label: '角色基线（BFLA）', children: <RoleBaselinesTab /> },
          { key: 'ownership', label: '对象权属（BOLA）', children: <OwnershipTab /> },
          { key: 'field-permissions', label: '字段权限', children: <FieldPermissionsTab /> },
        ]}
      />
    </Card>
  )
}
