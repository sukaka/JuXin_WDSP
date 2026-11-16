import { useEffect, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import {
  App as AntdApp,
  Button,
  Col,
  Descriptions,
  Form,
  Input,
  Row,
  Select,
  Typography,
} from 'antd'
import { ApiError } from '../../api/client'
import {
  API_AUTH_TYPE_META,
  API_DATA_LEVEL_META,
  API_LEVEL_META,
  apiEndpointsApi,
  assetProfileInput,
  type ApiAssetProfileInput,
  type ApiEndpointAsset,
} from '../../api/apiAssets'

interface Props {
  endpointId: string
  /** 已保存档案（详情查询返回；无记录为 null） */
  asset: ApiEndpointAsset | null | undefined
  /** 详情未加载完成时禁用保存，避免全量替换覆盖已存档案 */
  detailReady: boolean
  /** 近 7 天日均调用量（详情查询返回） */
  dailyRequests: number | undefined
  /** 互联网暴露展示值：是 / 否 / 未知（由暴露面判定派生，只读） */
  internetExposed: string
  canEdit: boolean
}

/** 资产档案：多标签 + 单位/系统/负责人/数据等级/API 等级/认证方式人工编辑（PATCH 全量替换，api_asset.edit 权限） */
export default function AssetProfileSection({
  endpointId,
  asset,
  detailReady,
  dailyRequests,
  internetExposed,
  canEdit,
}: Props) {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const [form] = Form.useForm<ApiAssetProfileInput>()
  const [dirty, setDirty] = useState(false)

  /** 切换接口或保存/外部刷新后，以服务端档案重置表单 */
  useEffect(() => {
    form.setFieldsValue(assetProfileInput(asset))
    setDirty(false)
  }, [form, endpointId, asset])

  const saveMut = useMutation({
    mutationFn: (values: ApiAssetProfileInput) =>
      apiEndpointsApi.update(endpointId, values),
    onSuccess: (r) => {
      message.success(r.message || '资产档案已保存')
      setDirty(false)
      void queryClient.invalidateQueries({ queryKey: ['api-endpoints'] })
    },
    onError: (e: unknown) =>
      message.error(e instanceof ApiError ? e.message : '资产档案保存失败'),
  })

  const save = async () => {
    const values = await form.validateFields()
    saveMut.mutate(assetProfileInput(asset, values))
  }

  return (
    <>
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 12,
          margin: '16px 0 12px',
          flexWrap: 'wrap',
        }}
      >
        <Typography.Title level={5} style={{ margin: 0 }}>
          资产档案
        </Typography.Title>
        {canEdit && (
          <Button
            size="small"
            type="primary"
            loading={saveMut.isPending}
            disabled={!dirty || !detailReady}
            onClick={() => void save()}
          >
            保存档案
          </Button>
        )}
      </div>
      <Descriptions
        column={2}
        size="small"
        bordered
        style={{ marginBottom: 12 }}
      >
        <Descriptions.Item label="互联网暴露">
          {internetExposed}
          <Typography.Text
            type="secondary"
            style={{ marginLeft: 8, fontSize: 12 }}
          >
            由暴露面判定派生，可在下方人工确认修改
          </Typography.Text>
        </Descriptions.Item>
        <Descriptions.Item label="调用量">
          {dailyRequests === undefined
            ? '-'
            : `日均 ${dailyRequests.toLocaleString('zh-CN')} 次（近 7 天）`}
        </Descriptions.Item>
      </Descriptions>
      <Form form={form} layout="vertical" onValuesChange={() => setDirty(true)}>
        <Row gutter={12}>
          <Col xs={24} md={12}>
            <Form.Item
              name="organization"
              label="所属单位"
              style={{ marginBottom: 12 }}
            >
              <Input
                size="small"
                maxLength={128}
                placeholder="如 XX集团金融事业部"
                disabled={!canEdit}
              />
            </Form.Item>
          </Col>
          <Col xs={24} md={12}>
            <Form.Item
              name="business_system"
              label="业务系统"
              style={{ marginBottom: 12 }}
            >
              <Input
                size="small"
                maxLength={128}
                placeholder="如 客户经营管理平台"
                disabled={!canEdit}
              />
            </Form.Item>
          </Col>
          <Col xs={24} md={8}>
            <Form.Item
              name="owner"
              label="系统负责人"
              style={{ marginBottom: 12 }}
            >
              <Input size="small" maxLength={128} disabled={!canEdit} />
            </Form.Item>
          </Col>
          <Col xs={24} md={8}>
            <Form.Item
              name="technical_owner"
              label="技术负责人"
              style={{ marginBottom: 12 }}
            >
              <Input size="small" maxLength={128} disabled={!canEdit} />
            </Form.Item>
          </Col>
          <Col xs={24} md={8}>
            <Form.Item
              name="data_owner"
              label="数据负责人"
              style={{ marginBottom: 12 }}
            >
              <Input size="small" maxLength={128} disabled={!canEdit} />
            </Form.Item>
          </Col>
          <Col xs={24} md={8}>
            <Form.Item
              name="data_level"
              label="数据等级"
              style={{ marginBottom: 12 }}
            >
              <Select
                size="small"
                disabled={!canEdit}
                options={Object.entries(API_DATA_LEVEL_META).map(
                  ([value, m]) => ({ value, label: m.label }),
                )}
              />
            </Form.Item>
          </Col>
          <Col xs={24} md={8}>
            <Form.Item
              name="api_level"
              label="API 等级"
              style={{ marginBottom: 12 }}
            >
              <Select
                size="small"
                disabled={!canEdit}
                options={Object.entries(API_LEVEL_META).map(([value, m]) => ({
                  value,
                  label: m.label,
                }))}
              />
            </Form.Item>
          </Col>
          <Col xs={24} md={8}>
            <Form.Item
              name="auth_type"
              label="认证方式"
              style={{ marginBottom: 12 }}
            >
              <Select
                size="small"
                disabled={!canEdit}
                options={Object.entries(API_AUTH_TYPE_META).map(
                  ([value, m]) => ({ value, label: m.label }),
                )}
              />
            </Form.Item>
          </Col>
          <Col span={24}>
            <Form.Item
              name="tags"
              label="标签（可多个，回车添加，最多 32 个）"
              style={{ marginBottom: 12 }}
            >
              <Select
                mode="tags"
                size="small"
                open={false}
                suffixIcon={null}
                maxCount={32}
                maxLength={64}
                placeholder="如 对账、第三方回调"
                disabled={!canEdit}
                tokenSeparators={[',', '，']}
              />
            </Form.Item>
          </Col>
        </Row>
      </Form>
    </>
  )
}
