import { Link, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  Alert,
  Button,
  Card,
  Descriptions,
  List,
  Space,
  Typography,
} from 'antd'
import {
  CheckCircleOutlined,
  FileSearchOutlined,
  StopOutlined,
} from '@ant-design/icons'
import { securityRegressionApi } from '../../api/securityRegression'
import StatusTag from '../../components/StatusTag'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import { useBreadcrumbObjectName } from '../../stores/breadcrumb'
import { formatDateTime } from '../../utils/format'
import { truncateHash } from '../../utils/stage3'
import {
  REG_DECLARED_META,
  REG_GATE_MODE_META,
  REG_LEVEL_META,
  REG_VERIFY_META,
  gateReasonAdvice,
} from '../../utils/securityRegression'

/**
 * 回归运行详情：摘要 + 门禁可用性实时评估（gate_assessment 为服务端按当前策略
 * 的只读评估，不产生判定留痕；发布时由发布器门禁终判）。不可用原因逐条给出
 * 文字原因与恢复动作（§8：不能只显示绿色百分比）。
 */
export default function SecurityRegressionDetailPage() {
  const { id = '' } = useParams()
  const detailQuery = useQuery({
    queryKey: ['security-regression', id],
    queryFn: () => securityRegressionApi.get(id),
    enabled: !!id,
  })
  const detail = detailQuery.data
  const run = detail?.run
  const gate = detail?.gate_assessment
  useBreadcrumbObjectName(run?.run_id)

  if (detailQuery.isError) {
    return <QueryErrorAlert error={detailQuery.error} />
  }
  if (!detail || !run || !gate) {
    return <Typography.Text type="secondary">加载中…</Typography.Text>
  }

  const missing = Math.max(0, run.counts.planned - run.counts.executed)

  return (
    <Space direction="vertical" size={16} style={{ display: 'flex' }}>
      <Card
        title={`回归运行 ${run.run_id}`}
        extra={
          <Link to={`/security-regressions/${run.id}/cases`}>
            <Button type="primary" icon={<FileSearchOutlined />}>
              查看用例差异
            </Button>
          </Link>
        }
      >
        <Descriptions column={{ xs: 1, sm: 2, md: 3 }} size="small" bordered>
          <Descriptions.Item label="运行级别">
            <StatusTag value={run.level} map={REG_LEVEL_META} />
          </Descriptions.Item>
          <Descriptions.Item label="服务端核验">
            <StatusTag value={run.verification_status} map={REG_VERIFY_META} />
          </Descriptions.Item>
          <Descriptions.Item label="声明状态（不采信）">
            <StatusTag value={run.declared_status} map={REG_DECLARED_META} />
          </Descriptions.Item>
          <Descriptions.Item label="计划/实际/缺失">
            <Typography.Text type={missing > 0 ? 'danger' : undefined}>
              {run.counts.planned} / {run.counts.executed} / {missing}
            </Typography.Text>
          </Descriptions.Item>
          <Descriptions.Item label="通过/失败">
            {run.counts.passed} / {run.counts.failed}
          </Descriptions.Item>
          <Descriptions.Item label="强制用例（总数/失败）">
            <Typography.Text type={run.counts.mandatory_failed > 0 ? 'danger' : undefined}>
              {run.counts.mandatory_total} / {run.counts.mandatory_failed}
            </Typography.Text>
          </Descriptions.Item>
          <Descriptions.Item label="跳过/阻塞/未运行">
            {run.counts.skipped} / {run.counts.blocked} / {run.counts.not_run}
          </Descriptions.Item>
          <Descriptions.Item label="签名密钥">
            <Typography.Text code>{run.signature_key_id}</Typography.Text>
          </Descriptions.Item>
          <Descriptions.Item label="导入时门禁策略版本">
            v{run.policy_version}
          </Descriptions.Item>
          <Descriptions.Item label="候选配置指纹" span={2}>
            <Typography.Text code copyable={{ text: run.config_fingerprint }}>
              {run.config_fingerprint}
            </Typography.Text>
          </Descriptions.Item>
          <Descriptions.Item label="manifest 哈希">
            <Typography.Text code>{truncateHash(run.manifest_sha256, 24)}</Typography.Text>
          </Descriptions.Item>
          <Descriptions.Item label="构建摘要">
            <Typography.Text code>{truncateHash(run.build_digest, 24)}</Typography.Text>
          </Descriptions.Item>
          <Descriptions.Item label="编译器">{run.compiler || '-'}</Descriptions.Item>
          <Descriptions.Item label="语料">
            {run.corpus_id} v{run.corpus_version}
          </Descriptions.Item>
          <Descriptions.Item label="语料/计划哈希" span={2}>
            <Space direction="vertical" size={0}>
              <Typography.Text code>{truncateHash(run.corpus_sha256, 24)}</Typography.Text>
              <Typography.Text code>{truncateHash(run.plan_sha256, 24)}</Typography.Text>
            </Space>
          </Descriptions.Item>
          <Descriptions.Item label="运行时间">
            {formatDateTime(run.run_started_at)} ~ {formatDateTime(run.run_finished_at)}
          </Descriptions.Item>
          <Descriptions.Item label="登记">
            {run.imported_by} · {formatDateTime(run.created_at)}
          </Descriptions.Item>
        </Descriptions>
        {run.verification_reasons.length > 0 && (
          <Alert
            style={{ marginTop: 16 }}
            type="info"
            showIcon
            message="服务端核验理由"
            description={
              <List
                size="small"
                dataSource={run.verification_reasons}
                renderItem={(r) => <List.Item>{r}</List.Item>}
              />
            }
          />
        )}
      </Card>

      <Card title="发布门禁可用性评估（按当前门禁策略实时评估）">
        <Space direction="vertical" size={12} style={{ display: 'flex' }}>
          {gate.usable_for_publish ? (
            <Alert
              type="success"
              showIcon
              icon={<CheckCircleOutlined />}
              message="本证据当前可用于支撑发布"
              description="发布时发布器门禁将对实际构建的候选指纹做终判；候选变化即需重新回归。"
            />
          ) : (
            <Alert
              type="error"
              showIcon
              icon={<StopOutlined />}
              message="本证据当前不可用于支撑发布"
            />
          )}
          <Descriptions column={{ xs: 1, sm: 2, md: 3 }} size="small">
            <Descriptions.Item label="门禁模式">
              <StatusTag value={gate.policy_mode} map={REG_GATE_MODE_META} />
            </Descriptions.Item>
            <Descriptions.Item label="要求级别">
              <StatusTag value={gate.required_level} map={REG_LEVEL_META} />
            </Descriptions.Item>
            <Descriptions.Item label="证据有效期">
              {Math.floor(gate.evidence_max_age_seconds / 86400)} 天
            </Descriptions.Item>
            <Descriptions.Item label="证据年龄">
              {Math.floor(gate.age_seconds / 3600)} 小时
            </Descriptions.Item>
            <Descriptions.Item label="是否超期">
              {gate.expired ? (
                <Typography.Text type="danger">已超期</Typography.Text>
              ) : (
                '未超期'
              )}
            </Descriptions.Item>
          </Descriptions>
          {gate.reasons.length > 0 && (
            <List
              size="small"
              bordered
              header={<Typography.Text strong>逐项理由与恢复动作</Typography.Text>}
              dataSource={gate.reasons}
              renderItem={(reason) => (
                <List.Item>
                  <Space direction="vertical" size={2}>
                    <Typography.Text>{reason}</Typography.Text>
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                      {gateReasonAdvice(reason)}
                    </Typography.Text>
                  </Space>
                </List.Item>
              )}
            />
          )}
          {gate.reasons.length === 0 && !gate.usable_for_publish && (
            <Alert
              type="warning"
              showIcon
              message="门禁未给出逐项理由"
              description="服务端未返回具体理由；请核对门禁策略与证据绑定后重试，或重新执行回归导入新证据。"
            />
          )}
        </Space>
      </Card>
    </Space>
  )
}
