import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Descriptions, Empty, Input, Modal, Space, Tag, Typography, message } from 'antd'
import { ApiError } from '../../api/client'
import { requestPcapApi, type RequestPcapItem, type RequestPcapLookup } from '../../api/requestPcap'
import { useAuthStore } from '../../stores/auth'
import { formatBytes, formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'

const integrityLabels = { UNVERIFIED: '未核验', PASS: '完整性通过', FAILED: '完整性失败', KEY_UNAVAILABLE: '密钥不可用' }
const integrityColors = { UNVERIFIED: 'default', PASS: 'success', FAILED: 'error', KEY_UNAVAILABLE: 'warning' } as const
const blockedReasons: Record<string, string> = {
  STORAGE_UNAVAILABLE: '证据已过期或存储不可用',
  EVIDENCE_INCOMPLETE: '存在丢包或截断，证据不完整',
  EVIDENCE_EXPIRED: '证据已超过保留期',
  UNIQUE_CORRELATION_REQUIRED: '请求关联不唯一，不能按单请求导出',
  PACKET_RANGE_REQUIRED: '缺少可验证的真实包范围',
  VERIFICATION_REQUIRED: '需要先完成完整性核验',
}

function errorMessage(error: unknown): string {
  return error instanceof ApiError ? error.message : '网络异常，请稍后重试'
}

export default function RequestPcapEvidence({ requestId }: { requestId: string }) {
  const permissions = useAuthStore((state) => state.user?.permissions)
  const canRead = hasPermission(permissions, 'request_pcap.read')
  const canVerify = hasPermission(permissions, 'request_pcap.verify')
  const canDownload = hasPermission(permissions, 'request_pcap.download')
  const queryClient = useQueryClient()
  const [verifyTarget, setVerifyTarget] = useState<RequestPcapItem | null>(null)
  const [downloadTarget, setDownloadTarget] = useState<RequestPcapItem | null>(null)
  const [reason, setReason] = useState('')
  const [password, setPassword] = useState('')
  const queryKey = ['request-pcap', requestId]
  const lookup = useQuery({
    queryKey,
    queryFn: () => requestPcapApi.lookup(requestId),
    enabled: canRead && Boolean(requestId),
    retry: false,
  })
  const verify = useMutation({
    mutationFn: ({ item, actionReason }: { item: RequestPcapItem; actionReason: string }) =>
      requestPcapApi.verify(item.artifact_id, requestId, actionReason),
    onSuccess: (item) => {
      queryClient.setQueryData<RequestPcapLookup>(queryKey, (current) => ({
        request_id: requestId,
        items: (current?.items ?? []).map((candidate) => candidate.artifact_id === item.artifact_id ? item : candidate),
      }))
      setVerifyTarget(null)
      setReason('')
      message.success('完整性核验通过')
    },
  })
  const grant = useMutation({
    mutationFn: ({ item, actionReason, secret }: { item: RequestPcapItem; actionReason: string; secret: string }) =>
      requestPcapApi.createGrant(item.artifact_id, requestId, actionReason, secret),
    onSuccess: (authorization) => {
      const anchor = document.createElement('a')
      anchor.href = requestPcapApi.downloadUrl(authorization)
      anchor.style.display = 'none'
      document.body.appendChild(anchor)
      anchor.click()
      anchor.remove()
      setPassword('')
      setReason('')
      setDownloadTarget(null)
      message.success('已发起单次派生下载，请检查浏览器下载结果')
    },
  })

  if (!canRead || !requestId) return null

  const closeVerify = () => {
    if (!verify.isPending) {
      setVerifyTarget(null)
      setReason('')
      verify.reset()
    }
  }
  const closeDownload = () => {
    if (!grant.isPending) {
      setDownloadTarget(null)
      setReason('')
      setPassword('')
      grant.reset()
    }
  }

  return (
    <section aria-label="PCAP 证据" style={{ marginBottom: 22 }}>
      <Typography.Title level={5} style={{ marginBottom: 6 }}>PCAP 证据</Typography.Title>
      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
        仅展示真实抓包与关联状态；不预览原始载荷。派生下载会再次核验并记录操作审计。
      </Typography.Text>
      {lookup.data?.truncated && <Alert type="info" style={{ marginTop: 10 }} showIcon message="证据较多，仅显示最新100条；指定证据的核验与下载不受列表截断影响" />}
      {lookup.isLoading ? <Typography.Paragraph type="secondary" style={{ marginTop: 14 }}>正在读取证据状态...</Typography.Paragraph> :
        lookup.isError ? <Alert style={{ marginTop: 14 }} type="warning" showIcon message="PCAP 证据不可用" description={errorMessage(lookup.error)} /> :
          (lookup.data?.items.length ?? 0) === 0 ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="没有已关联的 PCAP 证据；可能未启用抓包，或协议不支持可靠关联" /> :
            <div style={{ marginTop: 12 }}>
              {lookup.data?.items.map((item) => (
                <div key={item.artifact_id} style={{ padding: '14px 0', borderTop: '1px solid #e8edf3' }}>
                  <Space wrap size={8}>
                    <Typography.Text strong>{item.capture_point}</Typography.Text>
                    <Tag color={integrityColors[item.integrity_status]}>{integrityLabels[item.integrity_status]}</Tag>
                    <Tag color={item.storage_tier === 'HOT' ? 'blue' : 'default'}>{item.storage_tier === 'HOT' ? 'SSD 热层' : 'SAS 温层'}</Tag>
                    <Tag>{item.coverage === 'CONNECTION' ? '连接级证据' : item.coverage === 'REQUEST' ? '请求级证据' : '未确定范围'}</Tag>
                  </Space>
                  <Descriptions size="small" column={2} style={{ marginTop: 10 }}>
                    <Descriptions.Item label="证据 ID" span={2}><Typography.Text copyable style={{ fontSize: 12 }}>{item.artifact_id}</Typography.Text></Descriptions.Item>
                    <Descriptions.Item label="真实包范围">{item.first_packet_no && item.last_packet_no ? `${item.first_packet_no} – ${item.last_packet_no}` : '未确定'}</Descriptions.Item>
                    <Descriptions.Item label="包数 / 丢包">{item.packet_count} / {item.dropped_count}</Descriptions.Item>
                    <Descriptions.Item label="加密大小">{formatBytes(item.ciphertext_size_bytes)}</Descriptions.Item>
                    <Descriptions.Item label="到期时间">{formatDateTime(item.expires_at)}</Descriptions.Item>
                    <Descriptions.Item label="关联依据" span={2}>{item.match_basis}（候选 {item.candidate_count}）</Descriptions.Item>
                    {item.verification_error_code && <Descriptions.Item label="核验状态" span={2}><Typography.Text type="danger">{item.verification_error_code}</Typography.Text></Descriptions.Item>}
                  </Descriptions>
                  {item.coverage === 'CONNECTION' && <Typography.Text type="warning" style={{ display: 'block', fontSize: 12, marginBottom: 8 }}>连接级 PCAP 可能包含同连接的其他请求，导出前请确认授权范围。</Typography.Text>}
                  {!item.download_eligible && <Typography.Text type="secondary" style={{ display: 'block', fontSize: 12, marginBottom: 8 }}>{blockedReasons[item.download_blocked_reason ?? ''] ?? '当前不可下载'}</Typography.Text>}
                  <Space wrap>
                    {canVerify && <Button size="small" disabled={item.state === 'EXPIRED'} onClick={() => { setReason(''); setVerifyTarget(item) }}>完整性核验</Button>}
                    {canDownload && <Button size="small" type="primary" disabled={!item.download_eligible} onClick={() => { setReason(''); setDownloadTarget(item) }}>申请派生下载</Button>}
                  </Space>
                </div>
              ))}
            </div>}

      <Modal
        title="核验 PCAP 证据"
        open={verifyTarget !== null}
        onCancel={closeVerify}
        onOk={() => verifyTarget && verify.mutate({ item: verifyTarget, actionReason: reason.trim() })}
        okText="开始核验"
        confirmLoading={verify.isPending}
        okButtonProps={{ disabled: !reason.trim() }}
        destroyOnHidden
      >
        <Typography.Paragraph type="secondary">将流式读取加密证据并验证密文、分片及明文哈希，不生成明文临时文件。</Typography.Paragraph>
        <Input.TextArea aria-label="核验理由" value={reason} onChange={(event) => setReason(event.target.value)} maxLength={500} showCount placeholder="请填写核验理由（必填）" rows={3} />
        {verify.isError && <Alert type="error" showIcon style={{ marginTop: 12 }} message={errorMessage(verify.error)} />}
      </Modal>
      <Modal
        title="确认派生下载"
        open={downloadTarget !== null}
        onCancel={closeDownload}
        onOk={() => downloadTarget && grant.mutate({ item: downloadTarget, actionReason: reason.trim(), secret: password })}
        okText="授权并下载"
        confirmLoading={grant.isPending}
        okButtonProps={{ danger: true, disabled: !reason.trim() || !password }}
        destroyOnHidden
      >
        <Alert type="warning" showIcon message="原始 PCAP 可能含敏感数据" description="授权仅在当前账号和会话内有效 60 秒，只能使用一次；下载前会重新检查完整性、包范围与到期状态。" />
        <Input.TextArea aria-label="下载理由" value={reason} onChange={(event) => setReason(event.target.value)} maxLength={500} showCount placeholder="请填写取证用途（必填）" rows={3} style={{ marginTop: 16 }} />
        <Input.Password aria-label="当前账号密码" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" placeholder="请输入当前账号密码" style={{ marginTop: 12 }} />
        {grant.isError && <Alert type="error" showIcon style={{ marginTop: 12 }} message={errorMessage(grant.error)} />}
      </Modal>
    </section>
  )
}
