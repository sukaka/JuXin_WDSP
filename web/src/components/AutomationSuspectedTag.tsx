import { Tag, Tooltip } from 'antd'
import { RobotOutlined } from '@ant-design/icons'

interface Props {
  suspected: boolean
  /** 判定依据（stages=命中阶段集;indicator=首个指示信号），tooltip 展示 */
  basis?: string
}

/** 疑似自动化攻击徽标（attack_session.automation_suspected 派生标注；未标注时不渲染） */
export default function AutomationSuspectedTag({ suspected, basis }: Props) {
  if (!suspected) return null
  return (
    <Tooltip title={basis ? `判定依据：${basis}` : '有效阶段≥3 且命中自动化指示信号（无头/枚举/低慢类）'}>
      <Tag icon={<RobotOutlined />} color="red">
        疑似自动化攻击
      </Tag>
    </Tooltip>
  )
}
