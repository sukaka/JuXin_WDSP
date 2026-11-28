import { useCallback, useEffect, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Collapse,
  Drawer,
  Input,
  Popconfirm,
  Progress,
  Space,
  Steps,
  Switch,
  Tooltip,
  Typography,
  Upload,
} from 'antd'
import { InboxOutlined, ReloadOutlined, SafetyCertificateOutlined } from '@ant-design/icons'
import { ApiError, type UploadProgress } from '../../api/client'
import { rulePacksApi } from '../../api/rulePacks'
import { formatBytes } from '../../utils/format'
import RulePackJobProgress from './RulePackJobProgress'
import RulePackPreviewCard from './RulePackPreviewCard'
import {
  hasUnreadyStandby,
  isTerminalRulePackJobStatus,
  parsePreviewReport,
  RULEPACK_MAX_ARCHIVE_BYTES,
} from './rulePackMeta'
import type { RulePackCurrentStatus, RulePackItem, RulePackJob } from '../../types'

export interface RulePackUpdateDrawerProps {
  open: boolean
  currentStatus?: RulePackCurrentStatus | null
  pollIntervalMs?: number
  onClose: () => void
  onApplied?: (job: RulePackJob) => void
}

/**
 * 两步式纯离线 WAF 规则包热更新抽屉（§7.2）：
 * - Step 1：上传即校验（真实上传进度 0-100%，零现网影响，渲染验签/差异/策略预警/节点就绪卡）
 * - Step 2：二次确认一键生效（支持受控 HA 应急降级开关，1.5s 实时轮询 5 阶段流水线，成功后自动刷新规则库）
 */
export default function RulePackUpdateDrawer({
  open,
  currentStatus,
  pollIntervalMs,
  onClose,
  onApplied,
}: RulePackUpdateDrawerProps) {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()

  const [uploadProgress, setUploadProgress] = useState<UploadProgress | null>(null)
  const [uploadError, setUploadError] = useState<string | null>(null)
  const [uploadedPack, setUploadedPack] = useState<RulePackItem | null>(null)
  const [allowDegradedHA, setAllowDegradedHA] = useState(false)
  const [degradedReason, setDegradedReason] = useState('')
  const [degradedReasonError, setDegradedReasonError] = useState<string | null>(null)
  const [activeJob, setActiveJob] = useState<RulePackJob | null>(null)
  const [jobTerminal, setJobTerminal] = useState(false)
  const [jobSucceeded, setJobSucceeded] = useState(false)

  const resetState = useCallback(() => {
    setUploadProgress(null)
    setUploadError(null)
    setUploadedPack(null)
    setAllowDegradedHA(false)
    setDegradedReason('')
    setDegradedReasonError(null)
    setActiveJob(null)
    setJobTerminal(false)
    setJobSucceeded(false)
  }, [])

  useEffect(() => {
    if (!open) {
      resetState()
    }
  }, [open, resetState])

  const uploadMutation = useMutation({
    mutationFn: (file: File) => rulePacksApi.upload(file, setUploadProgress),
    onSuccess: (pack) => {
      setUploadProgress(null)
      setUploadError(null)
      setUploadedPack(pack)
      setAllowDegradedHA(false)
      setDegradedReason('')
      setDegradedReasonError(null)
      message.success(`规则包 ${pack.rulepack_version} 验签与预检通过（尚未变更现网）`)
      void queryClient.invalidateQueries({ queryKey: ['rule-packs'] })
    },
    onError: (e: unknown) => {
      setUploadProgress(null)
      const errMsg = e instanceof ApiError ? e.message : '规则包上传或校验失败'
      setUploadError(errMsg)
      message.error(errMsg)
    },
  })

  const applyMutation = useMutation({
    mutationFn: (vars: { id: string; allowDegraded: boolean; reason: string }) =>
      rulePacksApi.apply(vars.id, {
        allow_degraded_ha: vars.allowDegraded,
        degraded_reason: vars.allowDegraded ? vars.reason.trim() : '',
      }),
    onSuccess: (job) => {
      setActiveJob(job)
      const isDone = isTerminalRulePackJobStatus(job.status)
      setJobTerminal(isDone)
      setJobSucceeded(job.status === 'SUCCESS')
    },
    onError: (e: unknown) => {
      message.error(e instanceof ApiError ? e.message : '启动规则包应用任务失败')
    },
  })

  const handleJobFinished = useCallback(
    (job: RulePackJob) => {
      setActiveJob(job)
      setJobTerminal(true)
      const ok = job.status === 'SUCCESS'
      setJobSucceeded(ok)
      void queryClient.invalidateQueries({ queryKey: ['rule-packs'] })
      if (ok) {
        void queryClient.invalidateQueries({ queryKey: ['waf-rules'] })
        onApplied?.(job)
      }
    },
    [onApplied, queryClient],
  )

  const storageLegacyOrReadonly =
    Boolean(currentStatus) &&
    (currentStatus?.storage_mode === 'LEGACY_FLAT' || currentStatus?.writable === false)

  const preview = uploadedPack ? parsePreviewReport(uploadedPack.preview_report) : null
  const standbyUnready =
    hasUnreadyStandby(preview?.node_prechecks) ||
    Boolean(currentStatus?.ha_sync_enabled && hasUnreadyStandby(currentStatus.nodes))
  const hardBlocked = Boolean(
    preview?.split_brain_detected || preview?.active_upgrade_job || (preview && !preview.disk_ok),
  )

  const isBusy = uploadMutation.isPending || applyMutation.isPending || (activeJob !== null && !jobTerminal)

  const handleClose = () => {
    if (isBusy) return
    onClose()
  }

  const validateDegradedReason = (): boolean => {
    if (allowDegradedHA && !degradedReason.trim()) {
      const err = '开启应急降级时必须填写降级原因'
      setDegradedReasonError(err)
      message.warning(err)
      return false
    }
    setDegradedReasonError(null)
    return true
  }

  const handleConfirmApply = () => {
    if (!uploadedPack) return
    if (!validateDegradedReason()) return
    applyMutation.mutate({
      id: uploadedPack.id,
      allowDegraded: allowDegradedHA,
      reason: degradedReason,
    })
  }

  const uploadPercent =
    uploadProgress?.lengthComputable && uploadProgress.total > 0
      ? Math.min(100, Math.round((uploadProgress.loaded / uploadProgress.total) * 100))
      : 0

  const applyButtonDisabled =
    storageLegacyOrReadonly ||
    hardBlocked ||
    (standbyUnready && !allowDegradedHA) ||
    applyMutation.isPending

  const needsDegradedReasonInput = allowDegradedHA && !degradedReason.trim()

  const renderApplyAction = () => {
    if (!uploadedPack) return null
    const disabledTooltip = storageLegacyOrReadonly
      ? '版本化规则存储未就绪，暂不可应用'
      : hardBlocked
        ? '存在阻塞项（脑裂/系统升级中/磁盘不足），暂不可应用'
        : standbyUnready && !allowDegradedHA
          ? 'HA 备节点不可达或未就绪，默认禁止切换；如确需应急仅主节点生效，请展开上方应急降级开关并填写原因'
          : undefined

    const btn = (
      <Button
        type="primary"
        icon={<SafetyCertificateOutlined />}
        disabled={applyButtonDisabled}
        loading={applyMutation.isPending}
      >
        确认应用到网关
      </Button>
    )

    if (applyButtonDisabled) {
      return disabledTooltip ? <Tooltip title={disabledTooltip}>{btn}</Tooltip> : btn
    }

    if (needsDegradedReasonInput) {
      return (
        <Button
          type="primary"
          icon={<SafetyCertificateOutlined />}
          onClick={validateDegradedReason}
        >
          确认应用到网关
        </Button>
      )
    }

    return (
      <Popconfirm
        title={`确认将离线规则包 ${uploadedPack.rulepack_version} 应用到网关？`}
        description={
          allowDegradedHA
            ? '当前已开启 HA 应急降级模式：将仅在主节点生效，并立即记录高风险审计及 RULEPACK_NODE_DRIFT 告警。确定继续吗？'
            : '系统将自动完成规则快照落盘、网关校验发布与冒烟验证（失败自动保持原版本），随后自动同步规则库元数据。'
        }
        okText="确认应用"
        cancelText="取消"
        okButtonProps={allowDegradedHA ? { danger: true } : undefined}
        onConfirm={handleConfirmApply}
      >
        {btn}
      </Popconfirm>
    )
  }

  return (
    <Drawer
      title="更新离线规则包"
      open={open}
      onClose={handleClose}
      width={840}
      closable={!isBusy}
      maskClosable={!isBusy}
      keyboard={!isBusy}
      destroyOnHidden
      footer={
        <Space style={{ width: '100%', justifyContent: 'space-between' }}>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            100% 纯离线流程：上传阶段仅做验签与预检，确认应用后才切换现网网关规则。
          </Typography.Text>
          <Space>
            {activeJob === null && uploadedPack && (
              <Button
                icon={<ReloadOutlined />}
                disabled={applyMutation.isPending}
                onClick={resetState}
              >
                重新上传其他包
              </Button>
            )}
            {activeJob === null && uploadedPack && renderApplyAction()}
            {activeJob !== null && jobTerminal && !jobSucceeded && (
              <Button icon={<ReloadOutlined />} onClick={resetState}>
                返回重新上传
              </Button>
            )}
            <Button
              type={activeJob !== null && jobSucceeded ? 'primary' : 'default'}
              disabled={isBusy}
              onClick={handleClose}
            >
              {activeJob !== null && jobSucceeded ? '完成并关闭' : '关闭'}
            </Button>
          </Space>
        </Space>
      }
    >
      <Space direction="vertical" size={16} style={{ width: '100%' }}>
        <Steps
          size="small"
          current={activeJob ? 1 : 0}
          items={[
            { title: 'Step 1：上传即校验（零现网影响）' },
            { title: 'Step 2：确认一键生效与自动同步' },
          ]}
        />

        {storageLegacyOrReadonly && (
          <Alert
            type="warning"
            showIcon
            message={
              currentStatus?.storage_mode === 'LEGACY_FLAT'
                ? '当前未启用版本化规则包存储（LEGACY_FLAT 传统扁平模式）'
                : '版本化规则包存储目录当前不可写'
            }
            description="请先配置可写的版本化规则存储目录（WAF_RULES_STORE_DIR）并完成基础部署/升级迁移（gateway-rules 命名卷或裸机版本化目录）后再执行离线规则包热更新。"
          />
        )}

        {activeJob === null ? (
          !uploadedPack ? (
            <Space direction="vertical" size={14} style={{ width: '100%' }}>
              <Upload.Dragger
                accept=".tar.gz"
                maxCount={1}
                showUploadList={false}
                disabled={storageLegacyOrReadonly || uploadMutation.isPending}
                beforeUpload={(file) => {
                  if (storageLegacyOrReadonly || uploadMutation.isPending) {
                    return Upload.LIST_IGNORE
                  }
                  if (!file.name.toLowerCase().endsWith('.tar.gz')) {
                    message.error('仅支持 .tar.gz 格式的离线规则包')
                    return Upload.LIST_IGNORE
                  }
                  if (file.size > RULEPACK_MAX_ARCHIVE_BYTES) {
                    message.error('规则包大小超过 64 MiB 上限')
                    return Upload.LIST_IGNORE
                  }
                  setUploadError(null)
                  setUploadProgress(null)
                  uploadMutation.mutate(file)
                  return false
                }}
              >
                <p className="ant-upload-drag-icon">
                  <InboxOutlined />
                </p>
                <p className="ant-upload-text">点击或拖拽纯离线规则包（.tar.gz）到此区域</p>
                <p className="ant-upload-hint">
                  如：jiuzhang-wdsp-rulepack-20261201.1.tar.gz（上限 64 MiB，自动执行 Ed25519
                  签名验证、文件完整性校验与静态安全门禁，零现网副作用）
                </p>
              </Upload.Dragger>

              {uploadMutation.isPending && (
                <div role="status" aria-live="polite">
                  <Progress percent={uploadPercent} status="active" />
                  <Typography.Text type="secondary">
                    {uploadProgress?.lengthComputable &&
                    uploadProgress.total > 0 &&
                    uploadProgress.loaded >= uploadProgress.total
                      ? '规则包已上传，正在执行 Ed25519 验签、静态门禁与差异预检…'
                      : uploadProgress
                        ? `正在上传：${formatBytes(uploadProgress.loaded)}${uploadProgress.lengthComputable ? ` / ${formatBytes(uploadProgress.total)}` : ''}`
                        : '正在准备上传…'}
                  </Typography.Text>
                </div>
              )}

              {uploadError && (
                <Alert
                  type="error"
                  showIcon
                  message="上传验签或预检未通过（现网未受任何影响）"
                  description={uploadError}
                />
              )}
            </Space>
          ) : (
            <Space direction="vertical" size={14} style={{ width: '100%' }}>
              <RulePackPreviewCard pack={uploadedPack} />

              {standbyUnready && (
                <Space direction="vertical" size={10} style={{ width: '100%' }}>
                  <Alert
                    type="warning"
                    showIcon
                    message="检测到 HA 备节点不可达或未就绪"
                    description="默认采用严格一致策略（fail-closed）：备节点落盘前禁止切换主节点，防止主备规则版本分裂。若备机正在硬件维修且急需下发防护规则，可展开下方应急降级开关。"
                  />
                  <Collapse
                    size="small"
                    items={[
                      {
                        key: 'degraded-ha',
                        label: '应急降级：仅主节点生效',
                        children: (
                          <Space direction="vertical" size={10} style={{ width: '100%' }}>
                            <Space align="center">
                              <Switch
                                checked={allowDegradedHA}
                                aria-label="允许备机离线降级仅主节点生效"
                                onChange={(checked) => {
                                  setAllowDegradedHA(checked)
                                  if (!checked) setDegradedReasonError(null)
                                }}
                              />
                              <Typography.Text strong>
                                允许备机离线降级：仅主节点生效（默认关闭）
                              </Typography.Text>
                            </Space>
                            {allowDegradedHA && (
                              <>
                                <Alert
                                  type="error"
                                  showIcon
                                  message="高风险应急操作提醒"
                                  description="启用后将跳过不可达备节点并立即触发 HIGH 级别「HA 规则包版本漂移（RULEPACK_NODE_DRIFT）」系统告警与高风险审计。备机恢复上线后请在页头点击「补齐同步」。"
                                />
                                <div>
                                  <Input.TextArea
                                    rows={2}
                                    maxLength={500}
                                    showCount
                                    value={degradedReason}
                                    status={degradedReasonError ? 'error' : undefined}
                                    placeholder="必填：请填写应急降级原因（例如：备机硬件维护断电，急需下发 0day 防护规则）"
                                    onChange={(e) => {
                                      setDegradedReason(e.target.value)
                                      if (e.target.value.trim()) {
                                        setDegradedReasonError(null)
                                      }
                                    }}
                                  />
                                  {degradedReasonError && (
                                    <Typography.Text type="danger" style={{ fontSize: 12 }}>
                                      {degradedReasonError}
                                    </Typography.Text>
                                  )}
                                </div>
                              </>
                            )}
                          </Space>
                        ),
                      },
                    ]}
                  />
                </Space>
              )}
            </Space>
          )
        ) : (
          <RulePackJobProgress
            jobId={activeJob.id}
            initialJob={activeJob}
            pollIntervalMs={pollIntervalMs}
            onFinished={handleJobFinished}
          />
        )}
      </Space>
    </Drawer>
  )
}
