import {
  Alert,
  Card,
  Col,
  Collapse,
  Descriptions,
  List,
  Row,
  Space,
  Statistic,
  Table,
  Tag,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import {
  CheckCircleOutlined,
  CloseCircleOutlined,
  SafetyCertificateOutlined,
  WarningOutlined,
} from '@ant-design/icons'
import StatusTag from '../../components/StatusTag'
import { formatBytes, formatDateTime } from '../../utils/format'
import { truncateHash } from '../../utils/stage3'
import { ATTACK_TYPE_META, RULE_SEVERITY_META, RULE_SOURCE_META } from '../../utils/stage4'
import {
  parsePreviewReport,
  RULEPACK_POLICY_WARNING_KIND_META,
  RULEPACK_STATUS_META,
} from './rulePackMeta'
import type {
  RulePackChangeItem,
  RulePackItem,
  RulePackNodePrecheckStatus,
  RulePackPolicyImpactWarning,
} from '../../types'

export interface RulePackPreviewCardProps {
  pack: RulePackItem
}

const SAMPLE_COLUMNS: ColumnsType<RulePackChangeItem> = [
  {
    title: '规则ID',
    dataIndex: 'rule_id',
    width: 96,
    render: (v: number) => <Typography.Text code>{v}</Typography.Text>,
  },
  {
    title: '名称',
    dataIndex: 'name',
    ellipsis: true,
    render: (v: string) => v || '-',
  },
  {
    title: '攻击类型',
    dataIndex: 'attack_type',
    width: 130,
    render: (v: string) => <StatusTag value={v} map={ATTACK_TYPE_META} />,
  },
  {
    title: '风险等级',
    dataIndex: 'severity',
    width: 84,
    render: (v: string) => <StatusTag value={v} map={RULE_SEVERITY_META} />,
  },
  {
    title: '来源',
    dataIndex: 'rule_source',
    width: 120,
    render: (v: string) => <StatusTag value={v} map={RULE_SOURCE_META} />,
  },
  {
    title: '规则文件',
    dataIndex: 'file_name',
    width: 180,
    ellipsis: true,
    render: (v: string) => (
      <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
        {v || '-'}
      </Typography.Text>
    ),
  },
]

const NODE_PRECHECK_COLUMNS: ColumnsType<RulePackNodePrecheckStatus> = [
  {
    title: '节点',
    key: 'node',
    width: 180,
    render: (_, n) => (
      <Space size={6} wrap>
        <Typography.Text strong>{n.node_name}</Typography.Text>
        <Tag color={n.role === 'PRIMARY' ? 'gold' : 'blue'}>
          {n.role === 'PRIMARY' ? '主节点' : '备节点'}
        </Tag>
      </Space>
    ),
  },
  {
    title: '连通性',
    dataIndex: 'reachable',
    width: 90,
    render: (v: boolean) => (
      <Tag color={v ? 'green' : 'red'}>{v ? '在线' : '不可达'}</Tag>
    ),
  },
  {
    title: '规则包能力',
    dataIndex: 'rulepack_ready',
    width: 100,
    render: (v: boolean) => (
      <Tag color={v ? 'green' : 'orange'}>{v ? '就绪' : '未就绪'}</Tag>
    ),
  },
  {
    title: '当前版本',
    dataIndex: 'current_version',
    width: 140,
    render: (v?: string) => <Typography.Text code>{v || '-'}</Typography.Text>,
  },
  {
    title: '版本对齐',
    dataIndex: 'aligned',
    width: 96,
    render: (v: boolean) => (
      <Tag color={v ? 'green' : 'volcano'}>{v ? '已对齐' : '存在漂移'}</Tag>
    ),
  },
  {
    title: '诊断说明',
    dataIndex: 'error',
    render: (v?: string) =>
      v ? (
        <Typography.Text type="danger" style={{ fontSize: 12 }}>
          {v}
        </Typography.Text>
      ) : (
        '-'
      ),
  },
]

/**
 * 离线规则包验签、差异统计、客户策略影响预警与集群节点预检报告展示卡。
 * 同时复用于「更新离线规则包」Step 1 与「版本历史与回滚」预检详情弹窗。
 */
export default function RulePackPreviewCard({ pack }: RulePackPreviewCardProps) {
  const preview = parsePreviewReport(pack.preview_report)
  const diff = preview?.diff
  const policyWarnings: RulePackPolicyImpactWarning[] = preview?.policy_warnings ?? []
  const nodePrechecks = preview?.node_prechecks ?? []
  const changelog = preview?.changelog ?? []
  const highlightedCVEs = preview?.highlighted_cves ?? []
  const bySourceEntries = Object.entries(diff?.by_source ?? {}).filter(([, c]) => c > 0)

  const sampleItems = [
    ...(diff && (diff.added_samples?.length ?? 0) > 0
      ? [
          {
            key: 'added',
            label: `新增规则抽样（展示 ${diff.added_samples!.length} / 共 ${diff.added_count} 条）`,
            children: (
              <Table<RulePackChangeItem>
                size="small"
                rowKey="rule_id"
                columns={SAMPLE_COLUMNS}
                dataSource={diff.added_samples}
                pagination={false}
                scroll={{ x: 720 }}
              />
            ),
          },
        ]
      : []),
    ...(diff && (diff.updated_samples?.length ?? 0) > 0
      ? [
          {
            key: 'updated',
            label: `更新规则抽样（展示 ${diff.updated_samples!.length} / 共 ${diff.updated_count} 条）`,
            children: (
              <Table<RulePackChangeItem>
                size="small"
                rowKey="rule_id"
                columns={SAMPLE_COLUMNS}
                dataSource={diff.updated_samples}
                pagination={false}
                scroll={{ x: 720 }}
              />
            ),
          },
        ]
      : []),
    ...(diff && (diff.removed_samples?.length ?? 0) > 0
      ? [
          {
            key: 'removed',
            label: `移除规则抽样（展示 ${diff.removed_samples!.length} / 共 ${diff.removed_count} 条）`,
            children: (
              <Table<RulePackChangeItem>
                size="small"
                rowKey="rule_id"
                columns={SAMPLE_COLUMNS}
                dataSource={diff.removed_samples}
                pagination={false}
                scroll={{ x: 720 }}
              />
            ),
          },
        ]
      : []),
  ]

  return (
    <Space direction="vertical" size={14} style={{ width: '100%' }}>
      {pack.status === 'REJECTED' && pack.reject_reason && (
        <Alert
          type="error"
          showIcon
          message="该规则包校验未通过，已被拒绝"
          description={pack.reject_reason}
        />
      )}

      {preview && (
        <Card
          size="small"
          title={
            <Space size={6}>
              <SafetyCertificateOutlined style={{ color: '#52c41a' }} />
              <span>离线信任链与静态门禁核验</span>
            </Space>
          }
          extra={
            preview.verified_at ? (
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                核验时间：{formatDateTime(preview.verified_at)}
              </Typography.Text>
            ) : null
          }
        >
          <Space wrap size={[8, 8]}>
            <Tag
              color={preview.signature_verified ? 'success' : 'error'}
              icon={preview.signature_verified ? <CheckCircleOutlined /> : <CloseCircleOutlined />}
            >
              Ed25519 签名已验证
            </Tag>
            <Tag
              color={preview.integrity_verified ? 'success' : 'error'}
              icon={preview.integrity_verified ? <CheckCircleOutlined /> : <CloseCircleOutlined />}
            >
              文件完整性通过
            </Tag>
            <Tag
              color={preview.static_gate_passed ? 'success' : 'error'}
              icon={preview.static_gate_passed ? <CheckCircleOutlined /> : <CloseCircleOutlined />}
            >
              静态门禁通过
            </Tag>
            <Tag color="success" icon={<CheckCircleOutlined />}>
              版本兼容通过
            </Tag>
          </Space>
        </Card>
      )}

      <Descriptions size="small" bordered column={2}>
        <Descriptions.Item label="规则包版本">
          <Space size={6} wrap>
            <Typography.Text strong code>
              {pack.rulepack_version}
            </Typography.Text>
            {pack.is_builtin && <Tag color="geekblue">内置基线</Tag>}
            <StatusTag value={pack.status} map={RULEPACK_STATUS_META} />
          </Space>
        </Descriptions.Item>
        <Descriptions.Item label="CRS 版本">
          <Typography.Text code>{pack.crs_version || '-'}</Typography.Text>
          {preview?.previous_crs_version && preview.previous_crs_version !== pack.crs_version && (
            <Typography.Text type="secondary" style={{ marginLeft: 8, fontSize: 12 }}>
              （原 {preview.previous_crs_version}）
            </Typography.Text>
          )}
        </Descriptions.Item>
        <Descriptions.Item label="变更路径">
          {preview?.previous_version
            ? `${preview.previous_version} → ${pack.rulepack_version}`
            : pack.rulepack_version}
        </Descriptions.Item>
        <Descriptions.Item label="最低系统版本">
          {pack.min_system_version || '-'}
          {pack.coraza_compat ? `（Coraza ${pack.coraza_compat}）` : ''}
        </Descriptions.Item>
        <Descriptions.Item label="文件名">
          <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
            {pack.file_name || '-'}
          </Typography.Text>
        </Descriptions.Item>
        <Descriptions.Item label="文件大小">
          {pack.file_size > 0 ? formatBytes(pack.file_size) : '-'}
        </Descriptions.Item>
        {pack.file_sha256 && (
          <Descriptions.Item label="文件 SHA-256" span={2}>
            <Typography.Text
              code
              copyable={{ text: pack.file_sha256, tooltips: ['复制完整 SHA-256', '已复制'] }}
            >
              {truncateHash(pack.file_sha256, 20)}
            </Typography.Text>
          </Descriptions.Item>
        )}
      </Descriptions>

      {preview && (
        <>
          {preview.split_brain_detected && (
            <Alert
              type="error"
              showIcon
              message="检测到未处置的主备双主脑裂告警，禁止应用规则包"
              description="请先在「主备高可用」页面处置脑裂并恢复单主状态后再重试。"
            />
          )}

          {preview.active_upgrade_job && (
            <Alert
              type="error"
              showIcon
              message="当前存在正在执行的系统升级任务"
              description="系统升级与离线规则包热更新互斥，请等待系统升级完成后再执行应用。"
            />
          )}

          {!preview.disk_ok && (
            <Alert
              type="warning"
              showIcon
              message="规则存储分区可用磁盘空间不足"
              description={
                preview.disk_free_bytes >= 0
                  ? `当前可用空间仅 ${formatBytes(preview.disk_free_bytes)}，请清理磁盘空间后再应用规则包。`
                  : '请先检查规则存储目录磁盘剩余空间。'
              }
            />
          )}

          {diff && (
            <Card size="small" title="规则变更预览">
              <Space direction="vertical" size={12} style={{ width: '100%' }}>
                <Row gutter={12}>
                  <Col span={6}>
                    <Statistic
                      title="新增规则"
                      value={diff.added_count}
                      valueStyle={{ color: diff.added_count > 0 ? '#3f8600' : undefined }}
                    />
                  </Col>
                  <Col span={6}>
                    <Statistic
                      title="更新规则"
                      value={diff.updated_count}
                      valueStyle={{ color: diff.updated_count > 0 ? '#1677ff' : undefined }}
                    />
                  </Col>
                  <Col span={6}>
                    <Statistic
                      title="移除规则"
                      value={diff.removed_count}
                      valueStyle={{ color: diff.removed_count > 0 ? '#cf1322' : undefined }}
                    />
                  </Col>
                  <Col span={6}>
                    <Statistic title="总规则数" value={diff.total_rules} />
                  </Col>
                </Row>

                {bySourceEntries.length > 0 && (
                  <Space wrap size={[6, 6]}>
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                      按来源分布：
                    </Typography.Text>
                    {bySourceEntries.map(([source, count]) => (
                      <Tag key={source} color={RULE_SOURCE_META[source]?.color ?? 'default'}>
                        {RULE_SOURCE_META[source]?.label ?? source}：{count}
                      </Tag>
                    ))}
                  </Space>
                )}

                {highlightedCVEs.length > 0 && (
                  <div>
                    <Typography.Text strong style={{ fontSize: 13 }}>
                      重点覆盖漏洞（CVE）
                    </Typography.Text>
                    <div style={{ marginTop: 6 }}>
                      <Space wrap size={[6, 6]}>
                        {highlightedCVEs.map((cve) => (
                          <Tag key={cve} color="volcano">
                            {cve}
                          </Tag>
                        ))}
                      </Space>
                    </div>
                  </div>
                )}

                {changelog.length > 0 && (
                  <div>
                    <Typography.Text strong style={{ fontSize: 13 }}>
                      版本变更说明（Changelog）
                    </Typography.Text>
                    <ul style={{ margin: '6px 0 0', paddingLeft: 20 }}>
                      {changelog.map((line, idx) => (
                        <li key={`${idx}-${line}`}>
                          <Typography.Text>{line}</Typography.Text>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {sampleItems.length > 0 && <Collapse size="small" items={sampleItems} />}
              </Space>
            </Card>
          )}

          {policyWarnings.length > 0 ? (
            <Space direction="vertical" size={8} style={{ width: '100%' }}>
              <Alert
                type="warning"
                showIcon
                icon={<WarningOutlined />}
                message={`策略影响预警：检测到 ${policyWarnings.length} 项客户规则覆盖或例外策略可能受影响`}
                description="系统绝不会自动修改您已配置的规则覆盖（rule_overrides）、例外策略（exceptions）或自定义规则；请核对以下明细并在生效后按需人工复核。"
              />
              <Collapse
                size="small"
                defaultActiveKey={['policy-warnings']}
                items={[
                  {
                    key: 'policy-warnings',
                    label: `展开查看受影响的规则覆盖与例外策略明细（${policyWarnings.length} 项）`,
                    children: (
                      <List
                        size="small"
                        dataSource={policyWarnings}
                        renderItem={(w) => (
                          <List.Item>
                            <Space direction="vertical" size={2} style={{ width: '100%' }}>
                              <Space wrap size={6}>
                                <StatusTag value={w.kind} map={RULEPACK_POLICY_WARNING_KIND_META} />
                                {w.object_name && (
                                  <Typography.Text strong>{w.object_name}</Typography.Text>
                                )}
                                {w.rule_id ? (
                                  <Typography.Text code>规则 #{w.rule_id}</Typography.Text>
                                ) : null}
                                {w.tag ? <Tag color="blue">{w.tag}</Tag> : null}
                              </Space>
                              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                                {w.message}
                              </Typography.Text>
                            </Space>
                          </List.Item>
                        )}
                      />
                    ),
                  },
                ]}
              />
            </Space>
          ) : (
            <Alert
              type="info"
              showIcon
              message="策略影响检查通过：未发现受影响的规则覆盖或例外策略"
              description="离线规则包更新绝不会自动修改客户已配置的规则覆盖、例外策略或自定义规则。"
            />
          )}

          <Card
            size="small"
            title="节点就绪与环境预检"
            extra={
              <Space size={8}>
                {preview.disk_free_bytes >= 0 && (
                  <Tag color={preview.disk_ok ? 'green' : 'red'}>
                    磁盘可用：{formatBytes(preview.disk_free_bytes)}
                  </Tag>
                )}
              </Space>
            }
          >
            <Table<RulePackNodePrecheckStatus>
              size="small"
              rowKey={(n) => n.node_id || `${n.role}-${n.node_name}`}
              columns={NODE_PRECHECK_COLUMNS}
              dataSource={nodePrechecks}
              pagination={false}
              scroll={{ x: 640 }}
            />
          </Card>
        </>
      )}

      {!preview && pack.is_builtin && (
        <Alert
          type="info"
          showIcon
          message="系统内置基线快照"
          description="该版本为系统初始化时从内置规则种子创建的基线快照，无外部上传差异报告。"
        />
      )}
    </Space>
  )
}
