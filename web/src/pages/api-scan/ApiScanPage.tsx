import { Card, Tabs, Typography } from 'antd'
import AuthorizationsTab from './AuthorizationsTab'
import FindingsTab from './FindingsTab'
import JobsTab from './JobsTab'
import TargetsTab from './TargetsTab'

/**
 * API 主动扫描中心（WDSP / 阶段8 P1）：目标 → 授权 → 任务 → 发现 全链路管理。
 * 权限点：api_scan.read（查询）、api_scan.execute（授权签发/吊销、复测）、
 * api_scan.manage（目标维护、任务发起/启停/紧急停止、发现处置）；
 * 授权双人分离（建标人不得自签）由后端强制，前端仅提示。
 */
export default function ApiScanPage() {
  return (
    <Card title="API 主动扫描">
      <Typography.Paragraph type="secondary">
        在授权边界内对目标 API 做主动探测（未认证访问、下线 API 存活、敏感字段暴露、边界参数校验、
        对象级差异比对、方法枚举），发现可确认关联弱点并定向复测。
        能力默认关闭（settings api_scan.enabled），未启用时无法发起任务与复测；证据与样本均已脱敏截断。
      </Typography.Paragraph>
      <Tabs
        items={[
          { key: 'targets', label: '扫描目标', children: <TargetsTab /> },
          { key: 'authorizations', label: '扫描授权', children: <AuthorizationsTab /> },
          { key: 'jobs', label: '扫描任务', children: <JobsTab /> },
          { key: 'findings', label: '扫描发现', children: <FindingsTab /> },
        ]}
      />
    </Card>
  )
}
