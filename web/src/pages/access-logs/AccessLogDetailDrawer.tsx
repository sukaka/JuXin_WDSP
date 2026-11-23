import type { CSSProperties } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Descriptions, Drawer, Tag, Typography } from 'antd'
import { ApiError } from '../../api/client'
import { accessLogsApi } from '../../api/accessLogs'
import { formatDateTime } from '../../utils/format'
import RequestPcapEvidence from './RequestPcapEvidence'

const preStyle: CSSProperties = {
  margin: '4px 0 0',
  background: '#f5f5f5',
  padding: 8,
  borderRadius: 4,
  fontSize: 12,
  whiteSpace: 'pre-wrap',
  wordBreak: 'break-all',
  maxHeight: 240,
  overflow: 'auto',
}

/** 头体留痕渲染：全部按纯文本渲染（React 默认转义），防 XSS */
function PayloadSection({
  title,
  headers,
  body,
  truncated,
}: {
  title: string
  headers?: Record<string, string[]> | null
  body?: string
  truncated?: boolean
}) {
  const headerEntries = Object.entries(headers ?? {}).sort(([a], [b]) => a.localeCompare(b))
  return (
    <div style={{ marginBottom: 12 }}>
      <Typography.Text strong>{title}</Typography.Text>
      {truncated && (
        <Tag color="orange" style={{ marginLeft: 8 }}>
          已截断
        </Tag>
      )}
      {headerEntries.length === 0 && !body ? (
        <div>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            无记录
          </Typography.Text>
        </div>
      ) : (
        <>
          {headerEntries.length > 0 && (
            <pre style={preStyle}>
              {headerEntries.map(([k, vs]) => `${k}: ${(vs ?? []).join(', ')}`).join('\n')}
            </pre>
          )}
          {body && <pre style={preStyle}>{body}</pre>}
        </>
      )}
    </div>
  )
}

export default function AccessLogDetailDrawer({
  logId,
  onClose,
}: {
  logId: string | null
  onClose: () => void
}) {
  const detailQuery = useQuery({
    queryKey: ['access-log', logId],
    queryFn: () => accessLogsApi.get(logId as string),
    enabled: logId !== null,
  })

  const log = detailQuery.data

  return (
    <Drawer title="访问日志详情" open={logId !== null} onClose={onClose} width={720}>
      {detailQuery.isLoading ? (
        <Typography.Text type="secondary">加载中...</Typography.Text>
      ) : detailQuery.isError ? (
        <Alert
          type="error"
          showIcon
          message="加载访问日志详情失败"
          description={detailQuery.error instanceof ApiError ? detailQuery.error.message : undefined}
        />
      ) : log ? (
        <>
          <Typography.Title level={5}>基础信息</Typography.Title>
          <Descriptions column={2} size="small" bordered style={{ marginBottom: 16 }}>
            <Descriptions.Item label="时间">{formatDateTime(log.occurred_at)}</Descriptions.Item>
            <Descriptions.Item label="客户端 IP">
              {log.client_ip || '-'}
              {log.client_port ? `:${log.client_port}` : ''}
            </Descriptions.Item>
            <Descriptions.Item label="IP 归属地">
              {log.client_ip_geo?.label || '-'}
            </Descriptions.Item>
            <Descriptions.Item label="运营商">
              {log.client_ip_geo?.isp || '-'}
            </Descriptions.Item>
            <Descriptions.Item label="域名">{log.domain || '-'}</Descriptions.Item>
            <Descriptions.Item label="方法">{log.request_method || '-'}</Descriptions.Item>
            {/* 请求 URI 按纯文本渲染，React 自动转义，防 XSS */}
            <Descriptions.Item label="请求 URI" span={2}>
              <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12, wordBreak: 'break-all' }}>
                {log.request_uri || '-'}
              </Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="响应状态码">{log.response_status || '-'}</Descriptions.Item>
            <Descriptions.Item label="请求总耗时">{`${log.duration_ms} ms`}</Descriptions.Item>
            <Descriptions.Item label="上游首字节耗时">
              {log.ttfb_ms === null || log.ttfb_ms === undefined ? '未采集' : `${log.ttfb_ms} ms`}
            </Descriptions.Item>
            <Descriptions.Item label="请求大小">{`${log.bytes_in} B`}</Descriptions.Item>
            <Descriptions.Item label="响应大小">{`${log.bytes_out} B`}</Descriptions.Item>
            <Descriptions.Item label="WAF 动作">
              {log.waf_action === 'BLOCK' ? <Tag color="red">阻断</Tag> : <Tag>放行</Tag>}
            </Descriptions.Item>
            <Descriptions.Item label="网关节点">{log.gateway_node_id || '-'}</Descriptions.Item>
            <Descriptions.Item label="规范化 API">
              <Typography.Text code>{log.endpoint_key || log.path_template || '未识别'}</Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="请求 ID" span={2}>
              <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }} copyable>
                {log.request_id || '-'}
              </Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="Trace ID" span={2}>
              <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }} copyable={Boolean(log.trace_id)}>
                {log.trace_id || '未采集'}
              </Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="Span ID" span={2}>
              <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }} copyable={Boolean(log.span_id)}>
                {log.span_id || '未采集'}
              </Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="HTTP 版本">{log.http_version || '-'}</Descriptions.Item>
            <Descriptions.Item label="内容类型">{log.content_type || '-'}</Descriptions.Item>
            <Descriptions.Item label="用户代理" span={2}>
              {log.user_agent_summary || '-'}
            </Descriptions.Item>
            <Descriptions.Item label="来源地址" span={2}>
              {log.referer_summary || '-'}
            </Descriptions.Item>
          </Descriptions>

          <RequestPcapEvidence key={log.request_id} requestId={log.request_id} />

          <Typography.Title level={5}>请求/响应留痕</Typography.Title>
          <PayloadSection title="请求头" headers={log.request_headers} />
          <PayloadSection
            title="请求体"
            body={log.request_body}
            truncated={log.request_body_truncated}
          />
          <PayloadSection title="响应头" headers={log.response_headers} />
          <PayloadSection
            title="响应体"
            body={log.response_body}
            truncated={log.response_body_truncated}
          />
        </>
      ) : null}
    </Drawer>
  )
}
