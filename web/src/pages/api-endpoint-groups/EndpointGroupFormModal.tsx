import { useMemo, useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Alert, App as AntdApp, Form, Input, Modal, Select, Switch } from 'antd'
import { applicationsApi } from '../../api/applications'
import {
  API_ENDPOINT_GROUP_CODE_PATTERN,
  apiEndpointGroupsApi,
  normalizeApiEndpointGroupCode,
  type ApiEndpointGroup,
} from '../../api/apiEndpointGroups'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'

interface EndpointGroupFormValues {
  application_id: string
  code: string
  name: string
  description?: string
  enabled: boolean
}

export default function EndpointGroupFormModal({
  group,
  onClose,
  onSaved,
}: {
  group: ApiEndpointGroup | null
  onClose: () => void
  onSaved: () => void
}) {
  const { message } = AntdApp.useApp()
  const [form] = Form.useForm<EndpointGroupFormValues>()
  const [submitError, setSubmitError] = useState<string | null>(null)
  const editing = group !== null

  const applicationsQuery = useQuery({
    queryKey: ['applications', 'endpoint-group-options'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
  })
  const applicationOptions = useMemo(() => {
    const options = (applicationsQuery.data?.items ?? []).map((app) => ({
      value: app.id,
      label: `${app.name}（${app.code}）`,
    }))
    if (
      group &&
      !options.some((option) => option.value === group.application_id)
    ) {
      options.unshift({
        value: group.application_id,
        label: `${group.application_name || group.application_id}（当前应用）`,
      })
    }
    return options
  }, [applicationsQuery.data, group])

  const saveMutation = useMutation({
    mutationFn: (values: EndpointGroupFormValues) => {
      const common = {
        code: normalizeApiEndpointGroupCode(values.code),
        name: values.name.trim(),
        description: values.description?.trim() ?? '',
        enabled: values.enabled,
      }
      return editing
        ? apiEndpointGroupsApi.update(group.id, common)
        : apiEndpointGroupsApi.create({
            application_id: values.application_id,
            ...common,
          })
    },
    onSuccess: () => {
      message.success(editing ? '接口分组已更新' : '接口分组已创建')
      onSaved()
      onClose()
    },
    onError: (error: unknown) => {
      setSubmitError(
        error instanceof ApiError ? error.message : '保存接口分组失败',
      )
    },
  })

  return (
    <Modal
      title={editing ? `编辑分组：${group.name}` : '新建接口分组'}
      open
      onCancel={onClose}
      okText={editing ? '保存' : '创建'}
      cancelText="取消"
      confirmLoading={saveMutation.isPending}
      onOk={() => form.submit()}
      destroyOnHidden
    >
      {submitError ? (
        <Alert
          type="error"
          showIcon
          message="保存失败"
          description={submitError}
          style={{ marginBottom: 16 }}
        />
      ) : null}
      <QueryErrorAlert
        error={applicationsQuery.error}
        message="加载应用列表失败"
      />
      <Form<EndpointGroupFormValues>
        form={form}
        layout="vertical"
        initialValues={{
          application_id: group?.application_id,
          code: group?.code ?? '',
          name: group?.name ?? '',
          description: group?.description ?? '',
          enabled: group?.enabled ?? true,
        }}
        onFinish={(values) => {
          setSubmitError(null)
          saveMutation.mutate(values)
        }}
      >
        <Form.Item
          name="application_id"
          label="所属应用"
          rules={[{ required: true, message: '请选择所属应用' }]}
          extra={
            editing ? '分组所属应用不可变更' : '成员仅可选择该应用下的真实接口'
          }
        >
          <Select
            showSearch
            optionFilterProp="label"
            placeholder="选择应用"
            disabled={editing}
            loading={applicationsQuery.isLoading}
            options={applicationOptions}
          />
        </Form.Item>
        <Form.Item
          name="code"
          label="分组编码"
          normalize={(value: string | undefined) =>
            normalizeApiEndpointGroupCode(value ?? '')
          }
          rules={[
            { required: true, message: '请输入分组编码' },
            { max: 64, message: '分组编码不超过 64 个字符' },
            {
              pattern: API_ENDPOINT_GROUP_CODE_PATTERN,
              message: '须以大写字母开头，仅含大写字母、数字和下划线',
            },
          ]}
          extra="保存前自动去除首尾空白并转为大写"
        >
          <Input
            placeholder="如 ORDER_CENTER"
            maxLength={64}
            autoComplete="off"
          />
        </Form.Item>
        <Form.Item
          name="name"
          label="分组名称"
          rules={[
            { required: true, whitespace: true, message: '请输入分组名称' },
            { max: 128, message: '分组名称不超过 128 个字符' },
          ]}
        >
          <Input placeholder="如：订单中心" maxLength={128} />
        </Form.Item>
        <Form.Item
          name="description"
          label="业务说明"
          rules={[{ max: 512, message: '业务说明不超过 512 个字符' }]}
        >
          <Input.TextArea
            rows={3}
            maxLength={512}
            showCount
            placeholder="说明该组覆盖的业务功能与接口边界"
          />
        </Form.Item>
        <Form.Item name="enabled" label="启用状态" valuePropName="checked">
          <Switch checkedChildren="启用" unCheckedChildren="停用" />
        </Form.Item>
      </Form>
    </Modal>
  )
}
