import { useQuery } from '@tanstack/react-query'
import { Card, Col, Row, Space, Statistic, Typography } from 'antd'
import SmartTable from '../../../../components/SmartTable'
import type { ColumnsType } from 'antd/es/table'
import { aiUsageApi } from '../../../../api/ai'
import type { AiUsageByUser } from '../../../../api/ai'
import QueryErrorAlert from '../../../../components/QueryErrorAlert'

/** 配额成本：今日用量概览 + 按用户统计（近 7 天） */
export default function AiUsagePage() {
  const overviewQuery = useQuery({
    queryKey: ['ai-usage-overview'],
    queryFn: aiUsageApi.overview,
  })

  const byUserQuery = useQuery({
    queryKey: ['ai-usage-by-user'],
    queryFn: aiUsageApi.byUser,
  })

  const overview = overviewQuery.data

  const columns: ColumnsType<AiUsageByUser> = [
    { title: '用户名', dataIndex: 'username' },
    { title: '输入令牌', dataIndex: 'input_tokens', align: 'right' },
    { title: '输出令牌', dataIndex: 'output_tokens', align: 'right' },
    { title: '调用次数', dataIndex: 'model_calls', align: 'right' },
    {
      title: '预估成本',
      dataIndex: 'cost',
      align: 'right',
      render: (v: number) => `¥${v.toFixed(4)}`,
    },
  ]

  return (
    <Space direction="vertical" size={16} style={{ display: 'flex' }}>
      {overviewQuery.isError ? (
        <QueryErrorAlert error={overviewQuery.error} message="加载用量概览失败" />
      ) : (
        <Row gutter={[16, 16]}>
          <Col flex="1 1 180px">
            <Card>
              <Statistic
                title="今日输入令牌"
                value={overview?.today_input_tokens ?? 0}
                loading={overviewQuery.isLoading}
              />
            </Card>
          </Col>
          <Col flex="1 1 180px">
            <Card>
              <Statistic
                title="今日输出令牌"
                value={overview?.today_output_tokens ?? 0}
                loading={overviewQuery.isLoading}
              />
            </Card>
          </Col>
          <Col flex="1 1 180px">
            <Card>
              <Statistic
                title="模型调用次数"
                value={overview?.today_model_calls ?? 0}
                loading={overviewQuery.isLoading}
              />
            </Card>
          </Col>
          <Col flex="1 1 180px">
            <Card>
              <Statistic
                title="工具调用次数"
                value={overview?.today_tool_calls ?? 0}
                loading={overviewQuery.isLoading}
              />
            </Card>
          </Col>
          <Col flex="1 1 180px">
            <Card>
              <Statistic
                title="今日预估成本"
                value={overview?.today_cost ?? 0}
                precision={4}
                prefix="¥"
                loading={overviewQuery.isLoading}
              />
            </Card>
          </Col>
        </Row>
      )}

      <Card title="按用户统计（近 7 天）">
        {byUserQuery.isError ? (
          <QueryErrorAlert error={byUserQuery.error} message="加载按用户统计失败" />
        ) : (
          <SmartTable<AiUsageByUser>
            storageKey="ai-admin-usage"
            rowKey="username"
            loading={byUserQuery.isLoading}
            columns={columns}
            dataSource={byUserQuery.data}
            pagination={false}
          />
        )}
      </Card>

      <Typography.Text type="secondary">
        配额在服务端强制统计与限制；本地模型单价为 0 时成本为 0。
      </Typography.Text>
    </Space>
  )
}
