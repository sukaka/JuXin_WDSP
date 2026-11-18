import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App as AntdApp, Button, Card, Form, Input, Modal, Space, Switch, Tag, Typography } from 'antd'
import { ApiError } from '../../api/client'
import { requestPcapApi, type RequestPcapCaptureInput } from '../../api/requestPcap'
import { useAuthStore } from '../../stores/auth'
import { hasPermission } from '../../utils/permission'

interface CaptureForm {
  interface: string
  portsText: string
  hotDir: string
  warmDir: string
  reason: string
}

const STATE_META = {
  DISABLED: { color: 'default', text: '已关闭' },
  PENDING: { color: 'processing', text: '执行中' },
  ENABLED: { color: 'success', text: '已开启' },
  FAILED: { color: 'error', text: '执行失败' },
} as const

export default function CaptureControlCard() {
  const { message } = AntdApp.useApp()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const queryClient = useQueryClient()
  const [form] = Form.useForm<CaptureForm>()
  const [enableOpen, setEnableOpen] = useState(false)
  const [disableOpen, setDisableOpen] = useState(false)
  const [disableReason, setDisableReason] = useState('')
  const allowed = hasPermission(permissions, 'request_pcap.capture_control')
  const query = useQuery({
    queryKey: ['request-pcap-capture'],
    queryFn: requestPcapApi.getCapture,
    enabled: allowed,
    retry: false,
    refetchInterval: (current) => current.state.data?.state === 'PENDING' ? 3000 : false,
  })
  const mutation = useMutation({
    mutationFn: (input: RequestPcapCaptureInput) => requestPcapApi.setCapture(input),
    onSuccess: (status) => {
      queryClient.setQueryData(['request-pcap-capture'], status)
      setEnableOpen(false)
      setDisableOpen(false)
      setDisableReason('')
      message.success(status.state === 'PENDING' ? '指令已受理，正在等待宿主执行结果' : status.state === 'ENABLED' ? 'PCAP采集已开启' : 'PCAP采集已关闭')
      void query.refetch()
    },
    onError: (error: unknown) => message.error(error instanceof ApiError ? error.message : '操作失败'),
  })

  const status = query.data
  useEffect(() => {
    if (enableOpen && status) {
      form.setFieldsValue({
        interface: status.interface,
        portsText: status.ports?.join(','),
        hotDir: status.hot_dir,
        warmDir: status.warm_dir,
        reason: '',
      })
    }
  }, [enableOpen, status, form])

  if (!hasPermission(permissions, 'request_pcap.capture_control')) return null
  const meta = status ? STATE_META[status.state] : { color: 'default', text: '状态未知' }

  const enable = async () => {
    const values = await form.validateFields()
    mutation.mutate({
      enabled: true,
      interface: values.interface.trim(),
      ports: values.portsText.split(',').map((port) => Number(port.trim())),
      hot_dir: values.hotDir.trim(),
      warm_dir: values.warmDir.trim(),
      reason: values.reason.trim(),
    })
  }

  return (
    <>
      <Card type="inner" title="PCAP 取证采集">
        <Space direction="vertical" size={12} style={{ display: 'flex' }}>
          <Typography.Text type="secondary">
            开启后按指定网卡和端口保存加密请求证据；关闭立即停止新抓包，历史证据不自动删除。
          </Typography.Text>
          <Space size={12} wrap>
            <Switch
              checked={status?.state === 'ENABLED'}
              checkedChildren="开启"
              unCheckedChildren="关闭"
              loading={query.isLoading || mutation.isPending || status?.state === 'PENDING'}
              disabled={query.isError || !status}
              onChange={(checked) => checked ? setEnableOpen(true) : setDisableOpen(true)}
              aria-label="PCAP取证采集开关"
            />
            <Tag color={meta.color}>{meta.text}</Tag>
            {query.isError && <Button size="small" onClick={() => void query.refetch()}>重新获取状态</Button>}
          </Space>
          {status?.state === 'FAILED' && <Alert type="error" showIcon message="执行失败" description={status.message || '请检查宿主执行日志后重试'} />}
          {status?.state === 'PENDING' && <Alert type="info" showIcon message="宿主正在应用配置，管理 API 会短暂重启，请稍候" />}
          {status?.interface && (
            <Typography.Text type="secondary">
              {status.interface} · 端口 {status.ports.join(',')} · 热目录 {status.hot_dir} · 温目录 {status.warm_dir}
            </Typography.Text>
          )}
        </Space>
      </Card>

      <Modal
        title="开启 PCAP 取证采集"
        open={enableOpen}
        okText="开启并保存"
        confirmLoading={mutation.isPending}
        onOk={() => void enable()}
        onCancel={() => setEnableOpen(false)}
        destroyOnHidden={false}
      >
        <Alert
          type="warning"
          showIcon
          message="请按最小必要范围采集"
          description="原始流量可能包含账号、凭据等敏感数据。仅启用不会开放证据下载权限，下载仍需独立授权。"
          style={{ marginBottom: 16 }}
        />
        <Form form={form} layout="vertical" requiredMark>
          <Form.Item name="interface" label="采集网卡" rules={[{ required: true, message: '请输入实际网卡名称' }, { pattern: /^[A-Za-z0-9_.:-]{1,64}$/, message: '网卡名称格式不正确' }]}>
            <Input placeholder="例如 eth0，请按实际网卡填写" maxLength={64} />
          </Form.Item>
          <Form.Item name="portsText" label="采集端口" rules={[{ required: true, message: '请输入逗号分隔的端口' }, { pattern: /^\d+(,\d+)*$/, message: '仅支持明确端口，例如80,443，不支持区间' }]}>
            <Input placeholder="例如80,443" />
          </Form.Item>
          <Form.Item name="hotDir" label="SSD 热证据目录" rules={[{ required: true, message: '请输入热证据绝对路径' }, { pattern: /^\/[A-Za-z0-9._/-]+$/, message: '请输入受限字符的绝对路径' }]}>
            <Input placeholder="例如 /srv/jiuzhang-ssd/pcap" />
          </Form.Item>
          <Form.Item name="warmDir" label="SAS 温证据目录" rules={[{ required: true, message: '请输入温证据绝对路径' }, { pattern: /^\/[A-Za-z0-9._/-]+$/, message: '请输入受限字符的绝对路径' }]}>
            <Input placeholder="例如 /srv/jiuzhang-sas/pcap" />
          </Form.Item>
          <Form.Item name="reason" label="操作理由" rules={[{ required: true, whitespace: true, message: '请填写操作理由' }, { max: 500, message: '最多500字符' }]}>
            <Input.TextArea rows={3} maxLength={500} placeholder="说明本次开启采集的授权范围" />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title="关闭 PCAP 取证采集"
        open={disableOpen}
        okText="停止采集"
        okButtonProps={{ danger: true, disabled: !disableReason.trim() }}
        confirmLoading={mutation.isPending}
        onOk={() => mutation.mutate({ enabled: false, reason: disableReason.trim() })}
        onCancel={() => { setDisableOpen(false); setDisableReason('') }}
      >
        <Typography.Paragraph>将立即停止 pcapd，不再生成新的 PCAP 证据。已有证据按原保留期和授权策略处理，不会随关闭删除。</Typography.Paragraph>
        <Input.TextArea
          rows={3}
          maxLength={500}
          value={disableReason}
          onChange={(event) => setDisableReason(event.target.value)}
          placeholder="请填写停止采集的操作理由"
          aria-label="停止采集的操作理由"
        />
      </Modal>
    </>
  )
}
