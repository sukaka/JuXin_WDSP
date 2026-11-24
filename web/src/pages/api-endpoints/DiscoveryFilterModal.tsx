import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Form,
  Input,
  Modal,
  Select,
  Space,
  Switch,
  Typography,
} from 'antd'
import {
  apiEndpointsApi,
  type ApiDiscoveryFilterConfig,
} from '../../api/apiAssets'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'

interface Props {
  open: boolean
  canEdit: boolean
  onClose: () => void
}

function parseLines(raw: string): string[] {
  return raw
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
}

/** API 资产发现静态资源与非 API 过滤规则设置弹窗 */
export default function DiscoveryFilterModal({ open, canEdit, onClose }: Props) {
  const { message } = AntdApp.useApp()
  const qc = useQueryClient()

  const [excludeStatic, setExcludeStatic] = useState(true)
  const [filterNonAPI, setFilterNonAPI] = useState(true)
  const [extensions, setExtensions] = useState<string[]>([])
  const [excludePrefixesText, setExcludePrefixesText] = useState('')
  const [includePrefixesText, setIncludePrefixesText] = useState('')

  const filterQuery = useQuery({
    queryKey: ['api-endpoints', 'discovery-filter'],
    queryFn: () => apiEndpointsApi.getDiscoveryFilter(),
    enabled: open,
  })

  useEffect(() => {
    if (!open || !filterQuery.data?.config) return
    const cfg = filterQuery.data.config
    setExcludeStatic(cfg.exclude_static_assets)
    setFilterNonAPI(cfg.filter_non_api)
    setExtensions(cfg.exclude_extensions ?? [])
    setExcludePrefixesText((cfg.exclude_path_prefixes ?? []).join('\n'))
    setIncludePrefixesText((cfg.include_path_prefixes ?? []).join('\n'))
  }, [open, filterQuery.data])

  const saveMut = useMutation({
    mutationFn: (payload: ApiDiscoveryFilterConfig) =>
      apiEndpointsApi.updateDiscoveryFilter(payload),
    onSuccess: (res) => {
      message.success(res.message || '过滤规则已保存并生效')
      void qc.invalidateQueries({ queryKey: ['api-endpoints', 'discovery-filter'] })
      onClose()
    },
    onError: (e: unknown) =>
      message.error(e instanceof ApiError ? e.message : '保存失败'),
  })

  const defaultExtensions = filterQuery.data?.default_extensions ?? []

  const handleSave = () => {
    saveMut.mutate({
      exclude_static_assets: excludeStatic,
      filter_non_api: filterNonAPI,
      exclude_extensions: extensions,
      exclude_path_prefixes: parseLines(excludePrefixesText),
      include_path_prefixes: parseLines(includePrefixesText),
    })
  }

  return (
    <Modal
      title="API 发现过滤规则"
      open={open}
      width={680}
      onCancel={onClose}
      onOk={canEdit ? handleSave : undefined}
      okText="保存并生效"
      cancelText={canEdit ? '取消' : '关闭'}
      okButtonProps={{
        loading: saveMut.isPending,
        disabled: filterQuery.isLoading || !canEdit,
        style: canEdit ? undefined : { display: 'none' },
      }}
      destroyOnHidden
    >
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        title="仅过滤 API 资产发现与统计，不影响 WAF、访问控制与文件下载合规防护"
        description="保存后网关事件采集、旁路镜像、分布式 Agent 与云数据流投影立即共享生效；动态导出接口（如无静态后缀且携带 Content-Disposition 附件头）不会被误排除。"
      />
      <QueryErrorAlert error={filterQuery.error} />
      <Form layout="vertical">
        <Space size={32} style={{ marginBottom: 16 }} wrap>
          <Form.Item label="自动排除静态资源（图片/JS/CSS/字体/压缩包等）" style={{ marginBottom: 0 }}>
            <Switch
              checked={excludeStatic}
              disabled={!canEdit || filterQuery.isLoading}
              onChange={setExcludeStatic}
            />
          </Form.Item>
          <Form.Item label="仅发现判定为 API 的流量" style={{ marginBottom: 0 }}>
            <Switch
              checked={filterNonAPI}
              disabled={!canEdit || filterQuery.isLoading}
              onChange={setFilterNonAPI}
            />
          </Form.Item>
        </Space>

        <Form.Item
          label={
            <Space>
              <span>静态资源排除扩展名（仅作用于 GET / HEAD / OPTIONS）</span>
              {canEdit && defaultExtensions.length > 0 ? (
                <Button
                  type="link"
                  size="small"
                  style={{ padding: 0, height: 'auto' }}
                  onClick={() => setExtensions([...defaultExtensions])}
                >
                  恢复默认清单
                </Button>
              ) : null}
            </Space>
          }
          extra="支持复合扩展名（如 .tar.gz）；不建议添加 .json / .xml / .do / .php 等常见接口后缀。"
        >
          <Select
            mode="tags"
            style={{ width: '100%' }}
            disabled={!canEdit || !excludeStatic || filterQuery.isLoading}
            placeholder="输入扩展名后回车，如 .png、.js、.zip、.tar.gz"
            value={extensions}
            options={defaultExtensions.map((ext) => ({ value: ext, label: ext }))}
            onChange={(vals) => setExtensions(vals)}
            maxTagCount="responsive"
          />
        </Form.Item>

        <Form.Item
          label="自定义排除路径前缀（每行一条）"
          extra="按完整路径段前缀匹配，例如 /astro 匹配 /astro/page.js，但不会误伤 /astrology。"
        >
          <Input.TextArea
            rows={3}
            style={{ fontFamily: 'monospace' }}
            disabled={!canEdit || !excludeStatic || filterQuery.isLoading}
            placeholder={'/astro\n/_next/static\n/assets\n/static'}
            value={excludePrefixesText}
            onChange={(e) => setExcludePrefixesText(e.target.value)}
          />
        </Form.Item>

        <Form.Item
          label="强制保留白名单路径前缀（每行一条，最高优先级）"
          extra="命中白名单的路径即使包含静态扩展名，也不被静态排除规则过滤。"
          style={{ marginBottom: 0 }}
        >
          <Input.TextArea
            rows={2}
            style={{ fontFamily: 'monospace' }}
            disabled={!canEdit || filterQuery.isLoading}
            placeholder={'/api/public-files'}
            value={includePrefixesText}
            onChange={(e) => setIncludePrefixesText(e.target.value)}
          />
        </Form.Item>
      </Form>
      {!canEdit ? (
        <Typography.Text type="secondary" style={{ display: 'block', marginTop: 12 }}>
          当前账号仅有查看权限，需 api_asset.edit 权限才可修改过滤规则。
        </Typography.Text>
      ) : null}
    </Modal>
  )
}
