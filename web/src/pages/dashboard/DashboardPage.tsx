import { useQuery } from '@tanstack/react-query'
import { Alert, Badge, Card, Col, Descriptions, Row, Space, Tag } from 'antd'
import { authApi } from '../../api/auth'
import { ApiError } from '../../api/client'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import UserStatusTag from '../../components/UserStatusTag'
import { SYSTEM_NAME, SYSTEM_VERSION } from '../../constants'

export default function DashboardPage() {
  const user = useAuthStore((s) => s.user)
  const healthQuery = useQuery({
    queryKey: ['health'],
    queryFn: authApi.health,
    retry: 1,
    refetchInterval: 30_000,
  })

  return (
    <div>
      <Card style={{ marginBottom: 16 }}>
        <h2 style={{ margin: 0 }}>
          欢迎，{user?.display_name || user?.username}
        </h2>
        <p style={{ color: '#666', marginBottom: 0, marginTop: 8 }}>
          {SYSTEM_NAME} {SYSTEM_VERSION} 管理控制台
        </p>
      </Card>
      <Row gutter={16}>
        <Col xs={24} lg={12}>
          <Card title="账号信息" style={{ marginBottom: 16 }}>
            <Descriptions column={1} size="small">
              <Descriptions.Item label="用户名">{user?.username}</Descriptions.Item>
              <Descriptions.Item label="显示名">{user?.display_name}</Descriptions.Item>
              <Descriptions.Item label="所属角色">
                <Space wrap>
                  {user?.roles.map((r) => (
                    <Tag color="blue" key={r.code}>
                      {r.name}
                    </Tag>
                  ))}
                </Space>
              </Descriptions.Item>
              <Descriptions.Item label="账号状态">
                <UserStatusTag status={user?.status ?? ''} />
              </Descriptions.Item>
              <Descriptions.Item label="上次登录时间">
                {formatDateTime(user?.last_login_at)}
              </Descriptions.Item>
              <Descriptions.Item label="上次登录 IP">{user?.last_login_ip || '-'}</Descriptions.Item>
            </Descriptions>
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card title="系统运行状态" style={{ marginBottom: 16 }}>
            {healthQuery.isError ? (
              <Alert
                type="error"
                showIcon
                message="健康检查失败"
                description={
                  healthQuery.error instanceof ApiError
                    ? healthQuery.error.message
                    : '无法获取系统状态'
                }
              />
            ) : (
              <Descriptions column={1} size="small">
                <Descriptions.Item label="服务状态">
                  <Badge
                    status={healthQuery.data?.status === 'ok' ? 'success' : 'error'}
                    text={healthQuery.data?.status === 'ok' ? '运行中' : healthQuery.data?.status ?? '加载中'}
                  />
                </Descriptions.Item>
                <Descriptions.Item label="PostgreSQL">
                  <Badge
                    status={healthQuery.data?.postgres ? 'success' : 'error'}
                    text={healthQuery.data?.postgres ? '正常' : '异常'}
                  />
                </Descriptions.Item>
                <Descriptions.Item label="Valkey">
                  <Badge
                    status={healthQuery.data?.valkey ? 'success' : 'error'}
                    text={healthQuery.data?.valkey ? '正常' : '异常'}
                  />
                </Descriptions.Item>
              </Descriptions>
            )}
          </Card>
        </Col>
      </Row>
    </div>
  )
}
