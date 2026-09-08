import { useQuery } from '@tanstack/react-query'
import { Alert, Card, Col, List, Row, Space, Tag, Typography } from 'antd'
import { ApiError } from '../api/client'
import { securityEventsApi } from '../api/securityEvents'

/**
 * 修复建议卡片：按事件攻击类型展示处置知识库（分析步骤 / 修复建议 / 加固建议）。
 * 用于事件分析页结果下方；规则 ID 等上下文取自接口返回。
 */
export default function RemediationCard({ eventId }: { eventId: string }) {
  const query = useQuery({
    queryKey: ['security-event-remediation', eventId],
    queryFn: () => securityEventsApi.remediation(eventId),
    enabled: Boolean(eventId),
  })

  if (query.isLoading) {
    return (
      <Card size="small" title="修复建议" style={{ marginTop: 16 }}>
        <Typography.Text type="secondary">加载中...</Typography.Text>
      </Card>
    )
  }
  if (query.isError) {
    return (
      <Card size="small" title="修复建议" style={{ marginTop: 16 }}>
        <Alert
          type="warning"
          showIcon
          message="修复建议加载失败"
          description={query.error instanceof ApiError ? query.error.message : undefined}
        />
      </Card>
    )
  }

  const data = query.data
  if (!data) return null
  const { remediation: r, event } = data

  const renderList = (items: string[]) => (
    <List
      size="small"
      dataSource={items}
      renderItem={(item, idx) => (
        <List.Item style={{ padding: '6px 0' }}>
          <Typography.Text style={{ fontSize: 13, lineHeight: 1.7 }}>
            {idx + 1}. {item}
          </Typography.Text>
        </List.Item>
      )}
    />
  )

  return (
    <Card
      size="small"
      style={{ marginTop: 16 }}
      title={
        <Space wrap>
          修复建议
          <Tag color="geekblue">{r.attack_label}</Tag>
          {(event.rule_ids ?? []).length > 0 && (
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              命中规则：{event.rule_ids.join(' / ')}
            </Typography.Text>
          )}
        </Space>
      }
    >
      <Row gutter={[16, 8]}>
        <Col xs={24} lg={8}>
          <Typography.Text strong style={{ fontSize: 13 }}>
            如何分析研判
          </Typography.Text>
          {renderList(r.analyze_steps ?? [])}
        </Col>
        <Col xs={24} lg={8}>
          <Typography.Text strong style={{ fontSize: 13 }}>
            修复建议（开发侧）
          </Typography.Text>
          {renderList(r.fix_suggestions ?? [])}
        </Col>
        <Col xs={24} lg={8}>
          <Typography.Text strong style={{ fontSize: 13 }}>
            加固建议（防护侧）
          </Typography.Text>
          {renderList(r.hardening ?? [])}
        </Col>
      </Row>
    </Card>
  )
}
