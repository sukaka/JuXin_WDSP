import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App as AntdApp, Button, Modal, Select, Typography } from 'antd'
import { useNavigate } from 'react-router-dom'
import { ApiError } from '../../api/client'
import { applicationsApi } from '../../api/applications'
import { certificatesApi } from '../../api/certificates'
import { useAuthStore } from '../../stores/auth'
import { hasPermission } from '../../utils/permission'
import type { ApplicationItem, CertificateItem } from '../../types'

interface CertificateBindingModalProps {
  open: boolean
  operation: 'bind' | 'unbind'
  certificate?: CertificateItem
  application?: ApplicationItem
  onClose: () => void
}

async function listAllApplications(): Promise<ApplicationItem[]> {
  const items: ApplicationItem[] = []
  for (let page = 1; page <= 1000; page++) {
    const result = await applicationsApi.list({ page, page_size: 100 })
    const current = result.items ?? []
    items.push(...current)
    if (items.length >= result.total || current.length === 0) return items
  }
  throw new Error('应用数量超过可展示上限，请缩小操作范围')
}

async function listAllCertificates(): Promise<CertificateItem[]> {
  const items: CertificateItem[] = []
  for (let page = 1; page <= 1000; page++) {
    const result = await certificatesApi.list({ page, page_size: 100 })
    const current = result.items ?? []
    items.push(...current)
    if (items.length >= result.total || current.length === 0) return items
  }
  throw new Error('证书数量超过可展示上限，请缩小操作范围')
}

export default function CertificateBindingModal({
  open,
  operation,
  certificate,
  application,
  onClose,
}: CertificateBindingModalProps) {
  const { message } = AntdApp.useApp()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const [selectedID, setSelectedID] = useState('')
  const [saved, setSaved] = useState(false)

  const applicationsQuery = useQuery({
    queryKey: ['certificate-binding-applications', certificate?.id, operation],
    queryFn: async () => {
      const apps = await listAllApplications()
      if (operation === 'bind' || !certificate) return apps
      const bound = await certificatesApi.applications(certificate.id)
      const ids = new Set(bound.application_ids ?? [])
      return apps.filter((app) => ids.has(app.id))
    },
    enabled: open && Boolean(certificate) && !application,
  })
  const certificatesQuery = useQuery({
    queryKey: ['certificate-binding-certificates', application?.id],
    queryFn: listAllCertificates,
    enabled: open && operation === 'bind' && Boolean(application) && !certificate,
  })

  const mutation = useMutation({
    mutationFn: async () => {
      const certificateID = certificate?.id ?? selectedID
      const applicationID = application?.id ?? selectedID
      if (!certificateID || !applicationID) throw new Error('请选择证书和应用')
      if (operation === 'bind') return certificatesApi.bind(certificateID, applicationID)
      return certificatesApi.unbind(certificateID, applicationID)
    },
    onSuccess: () => {
      setSaved(true)
      message.success(operation === 'bind' ? '证书绑定关系已保存' : '证书解绑关系已保存')
      for (const key of ['certificates', 'certificate', 'cert-applications', 'app-certificates']) {
        void queryClient.invalidateQueries({ queryKey: [key] })
      }
    },
    onError: (error: unknown) => {
      message.error(error instanceof ApiError ? error.message : '操作失败')
    },
  })

  useEffect(() => {
    if (!open) return
    setSelectedID('')
    setSaved(false)
    mutation.reset()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, operation, certificate?.id, application?.id])

  const options = useMemo(() => {
    if (certificate && !application) {
      return (applicationsQuery.data ?? []).map((app) => ({
        value: app.id,
        label: `${app.name}（${app.code}）`,
      }))
    }
    return (certificatesQuery.data ?? []).map((cert) => ({
      value: cert.id,
      label: `${cert.name}（${cert.common_name}）`,
      disabled: ['EXPIRED', 'INVALID', 'KEY_MISMATCH'].includes(cert.status),
    }))
  }, [application, certificate, applicationsQuery.data, certificatesQuery.data])

  const needsSelection = !application || !certificate
  const optionError = applicationsQuery.error ?? certificatesQuery.error
  const canPublish = hasPermission(permissions, 'gateway_configs.preview')
  const title = operation === 'bind'
    ? application ? '绑定或替换证书' : '绑定证书到应用'
    : '解绑证书'

  const close = () => {
    setSelectedID('')
    setSaved(false)
    mutation.reset()
    onClose()
  }

  return (
    <Modal
      title={title}
      open={open}
      onCancel={close}
      onOk={() => mutation.mutate()}
      okText={operation === 'bind' ? '保存绑定' : '确认解绑'}
      okButtonProps={{
        danger: operation === 'unbind',
        disabled: needsSelection && !selectedID,
      }}
      confirmLoading={mutation.isPending}
      width={560}
      destroyOnHidden
    >
      {saved ? (
        <>
          <Alert
            type="success"
            showIcon
            message={operation === 'bind' ? '绑定关系已保存，尚未发布' : '解绑关系已保存，尚未发布'}
            description="只有配置发布成功后，网关才会使用新的证书关系。发布失败不会冒充已生效，可在配置发布页查看原因并重试。"
          />
          <div style={{ marginTop: 16, textAlign: 'right' }}>
            {canPublish && (
              <Button
                type="primary"
                onClick={() => {
                  close()
                  navigate('/config-publish')
                }}
              >
                去配置发布
              </Button>
            )}
          </div>
        </>
      ) : (
        <>
          <Alert
            type={operation === 'bind' ? 'info' : 'warning'}
            showIcon
            style={{ marginBottom: 16 }}
            message={operation === 'bind'
              ? '证书 CN/SAN 必须覆盖应用的全部 HTTPS 域名，且证书未过期'
              : '解绑只改变待发布配置关系；请完成配置发布，使网关与绑定关系一致'}
            description={operation === 'bind'
              ? '一个应用仅保留一张活动证书，选择新证书会替换旧证书。保存后需执行配置发布。'
              : '解绑不会删除证书文件，也不会删除历史审计记录。'}
          />
          {needsSelection && (
            <>
              <Typography.Text strong>
                {application ? '选择证书' : '选择应用'}
              </Typography.Text>
              <Select
                aria-label={application ? '选择证书' : '选择应用'}
                style={{ width: '100%', marginTop: 8 }}
                placeholder={application ? '请选择证书' : '请选择应用'}
                value={selectedID || undefined}
                options={options}
                loading={applicationsQuery.isLoading || certificatesQuery.isLoading}
                showSearch
                optionFilterProp="label"
                onChange={setSelectedID}
              />
            </>
          )}
          {optionError && (
            <Alert
              type="error"
              showIcon
              style={{ marginTop: 16 }}
              message="加载可选项失败"
              description={optionError instanceof ApiError ? optionError.message : '请稍后重试'}
            />
          )}
          {!needsSelection && certificate && application && (
            <Typography.Paragraph style={{ marginTop: 16, marginBottom: 0 }}>
              应用：<Typography.Text strong>{application.name}</Typography.Text>
              <br />
              证书：<Typography.Text strong>{certificate.name}</Typography.Text>
            </Typography.Paragraph>
          )}
        </>
      )}
    </Modal>
  )
}
