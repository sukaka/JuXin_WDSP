import { Button, Dropdown, Tooltip } from 'antd'
import { DownloadOutlined, DownOutlined } from '@ant-design/icons'

interface ExportDropdownProps {
  /** 导出筛选结果：携带当前页面的全部过滤条件 */
  onExportFiltered: () => void
  /** 导出全部：不带任何过滤条件 */
  onExportAll: () => void
  /** 导出按钮悬停提示（可选）：说明「导出筛选结果」实际生效的筛选维度，避免筛选条件被静默丢弃 */
  tooltip?: string
}

/** 日志导出下拉（各日志页统一交互）：默认显示「导出」，点击展开「导出筛选结果 / 导出全部」 */
export default function ExportDropdown({ onExportFiltered, onExportAll, tooltip }: ExportDropdownProps) {
  const button = (
    <Button icon={<DownloadOutlined />}>
      导出 <DownOutlined />
    </Button>
  )
  return (
    <Dropdown
      menu={{
        items: [
          { key: 'filtered', label: '导出筛选结果' },
          { key: 'all', label: '导出全部' },
        ],
        onClick: ({ key }) => (key === 'all' ? onExportAll() : onExportFiltered()),
      }}
    >
      {tooltip ? <Tooltip title={tooltip}>{button}</Tooltip> : button}
    </Dropdown>
  )
}
