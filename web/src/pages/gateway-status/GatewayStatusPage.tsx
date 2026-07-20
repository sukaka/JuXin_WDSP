import { useQuery } from '@tanstack/react-query'
import { Alert, Badge, Button, Card, Col, Descriptions, Row, Statistic, Typography } from 'antd'
import { ReloadOutlined } from '@ant-design/icons'
import { ApiError } from '../../api/client'
import { gatewayApi } from '../../api/gatewayConfig'
import StatusTag from '../../components/StatusTag'
import { PUBLISH_RESULT_META, truncateHash } from '../../utils/stage3'

export default function GatewayStatusPage() {
  const statusQuery = useQuery({
    queryKey: ['gateway-status'],
    queryFn: gatewayApi.status,
  })

  const data = statusQuery.data

  return (
    <Card
      title="网关状态"
      extra={
        <Button
          icon={<ReloadOutlined />}
          loading={statusQuery.isFetching}
          onClick={() => void statusQuery.refetch()}
        >
          刷新
        </Button>
      }
    >
      {statusQuery.isError ? (
        <Alert
          type="error"
          showIcon
          message="加载网关状态失败"
          description={statusQuery.error instanceof ApiError ? statusQuery.error.message : undefined}
        />
      ) : (
        <>
          <Row gutter={16} style={{ marginBottom: 24 }}>
            <Col xs={12} sm={6}>
              <Card size="small">
                <Statistic
                  title="网关运行状态"
                  valueRender={() =>
                    data ? (
                      data.gateway_up ? (
                        <Badge status="success" text="在线" />
                      ) : (
                        <Badge status="error" text="离线" />
                      )
                    ) : (
                      '-'
                    )
                  }
                />
              </Card>
            </Col>
            <Col xs={12} sm={6}>
              <Card size="small">
                <Statistic title="防护应用数" value={data?.application_count ?? '-'} />
              </Card>
            </Col>
            <Col xs={12} sm={6}>
              <Card size="small">
                <Statistic title="接入域名数" value={data?.domain_count ?? '-'} />
              </Card>
            </Col>
            <Col xs={12} sm={6}>
              <Card size="small">
                <Statistic title="在线源站数" value={data?.upstream_count ?? '-'} />
              </Card>
            </Col>
          </Row>

          {data && !data.gateway_up && data.gateway_error && (
            <Alert
              type="error"
              showIcon
              style={{ marginBottom: 16 }}
              message="网关连接异常"
              description={data.gateway_error}
            />
          )}

          <Descriptions column={1} size="small" bordered>
            <Descriptions.Item label="当前生效版本">
              {data?.current_version || '（无生效版本）'}
            </Descriptions.Item>
            <Descriptions.Item label="当前配置哈希">
              {data?.current_hash ? (
                <Typography.Text copyable={{ text: data.current_hash }} style={{ fontFamily: 'monospace' }}>
                  {truncateHash(data.current_hash)}
                </Typography.Text>
              ) : (
                '-'
              )}
            </Descriptions.Item>
            <Descriptions.Item label="最后发布结果">
              {data ? <StatusTag value={data.last_publish_result} map={PUBLISH_RESULT_META} /> : '-'}
            </Descriptions.Item>
            <Descriptions.Item label="最后发布时间">
              {data?.last_publish_at || '-'}
            </Descriptions.Item>
          </Descriptions>
        </>
      )}
    </Card>
  )
}
