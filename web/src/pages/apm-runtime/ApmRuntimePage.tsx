import { useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Card,
  Col,
  DatePicker,
  Radio,
  Row,
  Select,
  Space,
  Spin,
  Statistic,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import { apmApi } from '../../api/apm'
import EChart from '../../components/EChart'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import { SEARCH_RANGE_OPTIONS } from '../../utils/stage6'
import { apmRuntimeMetricOption } from '../../utils/apmCharts'
import {
  APM_SEARCH_WINDOW_HOURS,
  APM_TRACE_DATA_SOURCE_META,
  isCustomRangeOverCap,
  resolveApmTimeRange,
  type ApmRangeValue,
} from '../../utils/apm'

/** 运行时指标（权限 apm.runtime.read）：按服务/实例查看 GC、堆、线程等运行时指标小卡（30 秒轮询）；
 *  不同语言指标集不同，name/unit/description 如实展示；无 Agent 或空数据时降级提示 */
export default function ApmRuntimePage() {
  const { message } = AntdApp.useApp()
  const [range, setRange] = useState('1h')
  const [customRange, setCustomRange] = useState<ApmRangeValue>(null)
  const [service, setService] = useState<string | undefined>()
  const [instanceId, setInstanceId] = useState<string | undefined>()

  const timeParams = useMemo(() => resolveApmTimeRange(range, customRange), [range, customRange])

  // 服务下拉数据源：当前时间窗内的服务清单（上限 100）
  const servicesQuery = useQuery({
    queryKey: ['apm', 'services', 'runtime-filter-options', timeParams],
    queryFn: () => apmApi.services({ ...timeParams, page: 1, page_size: 100 }),
    retry: false,
  })

  const runtimeQuery = useQuery({
    queryKey: ['apm', 'runtime', timeParams, service, instanceId],
    queryFn: () =>
      apmApi.runtime({ ...timeParams, service, instance_id: instanceId }),
    refetchInterval: 30000,
  })

  // 实例下拉选项随响应累积合并：选中实例后服务端仅返回该实例，避免选项消失
  const [instanceOptions, setInstanceOptions] = useState<Map<string, string>>(new Map())
  useEffect(() => {
    const instances = runtimeQuery.data?.instances
    if (!instances?.length) return
    setInstanceOptions((prev) => {
      const next = new Map(prev)
      for (const inst of instances) {
        if (inst.instance_id) next.set(inst.instance_id, inst.service_name)
      }
      return next
    })
  }, [runtimeQuery.data])

  const data = runtimeQuery.data
  const dsMeta = data ? APM_TRACE_DATA_SOURCE_META[data.data_source] : undefined

  return (
    <Card
      title="运行时指标"
      extra={
        <Space>
          {data && (
            <Tag color={dsMeta?.color ?? 'default'}>
              数据来源：{dsMeta?.label ?? data.data_source}
            </Tag>
          )}
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            30 秒自动刷新
          </Typography.Text>
        </Space>
      }
    >
      <Space style={{ marginBottom: 16 }} wrap>
        <Radio.Group
          value={range}
          onChange={(e) => setRange(String(e.target.value))}
          options={[...SEARCH_RANGE_OPTIONS, { value: 'custom', label: '自定义' }]}
          optionType="button"
          size="small"
        />
        {range === 'custom' && (
          <DatePicker.RangePicker
            showTime
            value={customRange}
            onChange={(v) => {
              if (isCustomRangeOverCap(v, APM_SEARCH_WINDOW_HOURS)) {
                message.warning('查询窗口不能超过 24 小时')
                return
              }
              setCustomRange(v)
            }}
            size="small"
          />
        )}
        <Select
          placeholder="全部服务"
          allowClear
          showSearch
          optionFilterProp="label"
          style={{ width: 220 }}
          loading={servicesQuery.isLoading}
          options={(servicesQuery.data?.items ?? []).map((s) => ({
            value: s.app,
            label: `${s.name || s.app}（${s.app}）`,
          }))}
          onChange={(v) => {
            setService(v)
            setInstanceId(undefined)
          }}
        />
        <Select
          placeholder="全部实例"
          allowClear
          showSearch
          optionFilterProp="label"
          style={{ width: 260 }}
          value={instanceId}
          options={[...instanceOptions.entries()].map(([id, svc]) => ({
            value: id,
            label: `${id}（${svc}）`,
          }))}
          onChange={(v) => setInstanceId(v)}
        />
      </Space>

      {runtimeQuery.isLoading ? (
        <div style={{ textAlign: 'center', padding: 48 }}>
          <Spin />
        </div>
      ) : runtimeQuery.isError ? (
        <QueryErrorAlert error={runtimeQuery.error} message="加载运行时指标失败" />
      ) : data && data.data_source === 'agentless' ? (
        <Alert
          type="warning"
          showIcon
          message="运行时指标需接入 Agent"
          description="当前为无 Agent 数据来源，GC / 堆 / 线程等运行时指标不可用；请在「Agent 管理」页创建注册令牌并为服务接入 Agent 后刷新本页。"
        />
      ) : data && data.instances.length === 0 ? (
        <Alert
          type="info"
          showIcon
          message="暂无运行时指标数据"
          description="当前时间窗内没有实例上报运行时指标；请确认服务已接入 Agent 且处于在线状态。"
        />
      ) : data ? (
        <Space direction="vertical" size={16} style={{ display: 'flex' }}>
          {data.note && <Alert type="info" showIcon message={data.note} />}
          {data.instances.map((inst) => (
            <Card
              key={inst.instance_id}
              size="small"
              title={
                <Space>
                  <span>{inst.service_name || '-'}</span>
                  <Typography.Text code style={{ fontSize: 12 }}>
                    {inst.instance_id}
                  </Typography.Text>
                </Space>
              }
            >
              {(inst.metrics ?? []).length === 0 ? (
                <Alert type="info" showIcon message="该实例暂无指标数据" />
              ) : (
                <Row gutter={[12, 12]}>
                  {inst.metrics.map((m) => (
                    <Col key={m.name} xs={24} md={12} xl={8}>
                      <Card
                        size="small"
                        title={
                          <Tooltip title={m.description || m.name}>
                            <Typography.Text style={{ fontSize: 13 }}>{m.name}</Typography.Text>
                          </Tooltip>
                        }
                      >
                        <Statistic
                          value={m.latest_value}
                          suffix={m.unit || undefined}
                          valueStyle={{ fontSize: 20 }}
                        />
                        <EChart option={apmRuntimeMetricOption(m)} height={140} ariaLabel={`${m.name} 指标趋势`} />
                      </Card>
                    </Col>
                  ))}
                </Row>
              )}
            </Card>
          ))}
        </Space>
      ) : null}
    </Card>
  )
}
