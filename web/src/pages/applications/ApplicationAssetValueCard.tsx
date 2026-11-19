import {
  Alert,
  Card,
  Col,
  Row,
  Space,
  Spin,
  Statistic,
  Table,
  Tag,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { useQuery } from '@tanstack/react-query'
import {
  apiApplicationAssetsApi,
  type ApiApplicationValueDimension,
} from '../../api/apiAssets'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import { useAuthStore } from '../../stores/auth'
import { ASSET_VALUE_DIMENSION_LABELS } from '../../utils/i18nLabels'
import { hasPermission } from '../../utils/permission'

const LEVEL_META: Record<string, { color: string; label: string }> = {
  LOW: { color: 'green', label: '低' },
  MEDIUM: { color: 'gold', label: '中' },
  HIGH: { color: 'orange', label: '高' },
  CRITICAL: { color: 'red', label: '极高' },
}

interface Props {
  applicationId: string
}

export default function ApplicationAssetValueCard({ applicationId }: Props) {
  const permissions = useAuthStore((state) => state.user?.permissions)
  const canRead = hasPermission(permissions, 'api_asset.read')
  const query = useQuery({
    queryKey: ['application-asset-value', applicationId],
    queryFn: () => apiApplicationAssetsApi.value(applicationId),
    enabled: canRead && applicationId !== '',
  })
  const value = query.data
  const coverage =
    value && value.endpoint_count > 0
      ? Math.round((value.scored_count / value.endpoint_count) * 10000) / 100
      : 0

  const dimensionColumns: ColumnsType<ApiApplicationValueDimension> = [
    {
      title: '评分维度',
      dataIndex: 'name',
      render: (name: string) => ASSET_VALUE_DIMENSION_LABELS[name] ?? name,
    },
    {
      title: '平均分',
      dataIndex: 'average_score',
      align: 'right',
      render: (score: number) => score.toFixed(2),
    },
    {
      title: '原始满分',
      dataIndex: 'max',
      width: 120,
      align: 'right',
    },
  ]

  return (
    <Card title="API 资产价值（按接口评分聚合）">
      <Typography.Paragraph type="secondary">
        聚合该应用非忽略接口的已有评分，反映资产价值而非漏洞风险；未评分接口不计入平均分。
      </Typography.Paragraph>
      {!canRead ? (
        <Alert
          type="info"
          showIcon
          message="缺少「API 资产查看」权限，无法查看应用资产价值"
        />
      ) : (
        <>
          <QueryErrorAlert error={query.error} />
          {query.isLoading ? (
            <Spin size="small" />
          ) : value ? (
            <>
              <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
                <Col flex="1 1 140px">
                  <Statistic
                    title="平均得分"
                    value={value.average_score}
                    precision={2}
                    suffix={`/ ${value.max_total}`}
                  />
                </Col>
                <Col flex="1 1 140px">
                  <Statistic title="最高得分" value={value.max_score} />
                </Col>
                <Col flex="1 1 140px">
                  <Statistic title="接口总数" value={value.endpoint_count} />
                </Col>
                <Col flex="1 1 140px">
                  <Statistic
                    title="评分覆盖率"
                    value={coverage}
                    precision={2}
                    suffix="%"
                  />
                </Col>
              </Row>
              <Space
                size={8}
                wrap
                style={{ display: 'flex', marginBottom: 12 }}
              >
                <Typography.Text strong>综合等级</Typography.Text>
                {value.level ? (
                  <Tag color={LEVEL_META[value.level]?.color}>
                    {LEVEL_META[value.level]?.label ?? value.level}
                  </Tag>
                ) : (
                  <Tag>未评分</Tag>
                )}
                <Typography.Text type="secondary">
                  已评分 {value.scored_count}，未评分 {value.unscored_count}
                </Typography.Text>
              </Space>
              {value.scored_count === 0 && (
                <Alert
                  type="info"
                  showIcon
                  message="该应用尚无可聚合的接口评分"
                  style={{ marginBottom: 16 }}
                />
              )}
              <Space
                size={6}
                wrap
                style={{ display: 'flex', marginBottom: 16 }}
              >
                <Typography.Text type="secondary">等级分布</Typography.Text>
                {Object.entries(value.level_distribution)
                  .sort(([left], [right]) => left.localeCompare(right))
                  .map(([level, count]) => (
                    <Tag key={level} color={LEVEL_META[level]?.color}>
                      {LEVEL_META[level]?.label ?? level}：{count}
                    </Tag>
                  ))}
              </Space>
              {value.dimensions.length > 0 && (
                <Table<ApiApplicationValueDimension>
                  size="small"
                  rowKey="name"
                  columns={dimensionColumns}
                  dataSource={value.dimensions}
                  pagination={false}
                />
              )}
            </>
          ) : null}
        </>
      )}
    </Card>
  )
}
