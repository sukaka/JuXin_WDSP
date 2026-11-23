import { App as AntdApp, Button, Dropdown, message as staticMessage, Space, Tooltip, Typography } from 'antd'
import type { MenuProps } from 'antd'
import { DownloadOutlined, DownOutlined, QuestionCircleOutlined } from '@ant-design/icons'

/** 单次按勾选 ID 导出的上限（与后端 validation.MaxExportSelectedIDs 保持一致） */
export const MAX_EXPORT_SELECTED = 200

export interface ExportDropdownProps {
  /** 导出已选：仅当存在勾选项时可用（已选的内容才导出） */
  onExportSelected?: () => void
  /** 当前已勾选条数（配合 onExportSelected 使用） */
  selectedCount?: number
  /** 一键清空当前勾选项（可选；传入后已选 > 0 时在按钮旁展示已选计数与清空入口） */
  onClearSelection?: () => void
  /** 单次选择导出条数上限（默认 200） */
  maxSelected?: number
  /** 导出筛选结果：携带当前页面的全部过滤条件 */
  onExportFiltered: () => void
  /** 导出全部：不带页面过滤条件（可选） */
  onExportAll?: () => void
  /** 按钮文案（默认「导出」） */
  label?: string
  /** 可选导出补充说明：渲染为按钮左侧独立提示图标（placement="left"），绝不包裹下拉按钮以免遮挡菜单 */
  tooltip?: string
}

/**
 * 列表导出下拉（全站统一交互）：
 * - 点击展开（trigger={['click']}，placement="bottomRight"），避免鼠标路过或提示层遮挡菜单与下方工具栏；
 * - 支持「导出已选（仅勾选内容）/ 导出筛选结果 / 导出全部」三种模式。
 */
export default function ExportDropdown({
  onExportSelected,
  selectedCount = 0,
  onClearSelection,
  maxSelected = MAX_EXPORT_SELECTED,
  onExportFiltered,
  onExportAll,
  label = '导出',
  tooltip,
}: ExportDropdownProps) {
  const { message } = AntdApp.useApp()
  const notify = message ?? staticMessage

  const items: NonNullable<MenuProps['items']> = []
  if (onExportSelected) {
    items.push({
      key: 'selected',
      label: selectedCount > 0 ? `导出已选（${selectedCount}）` : '导出已选（请先勾选）',
      disabled: selectedCount <= 0,
    })
  }
  items.push({ key: 'filtered', label: '导出筛选结果' })
  if (onExportAll) {
    items.push({ key: 'all', label: '导出全部' })
  }

  const handleMenuClick: MenuProps['onClick'] = ({ key }) => {
    if (key === 'selected') {
      if (!onExportSelected || selectedCount <= 0) return
      if (selectedCount > maxSelected) {
        notify.warning(
          `单次选择导出最多支持 ${maxSelected} 条，当前已选 ${selectedCount} 条，请缩减勾选项或改用「导出筛选结果」`,
        )
        return
      }
      onExportSelected()
      return
    }
    if (key === 'all') {
      onExportAll?.()
      return
    }
    onExportFiltered()
  }

  const buttonLabel =
    selectedCount > 0 && !onClearSelection ? `${label}（已选 ${selectedCount}）` : label

  return (
    <Space size={8} align="center">
      {selectedCount > 0 && onClearSelection && (
        <Space size={4} align="center">
          <Typography.Text type="secondary" style={{ fontSize: 12, whiteSpace: 'nowrap' }}>
            已选 {selectedCount} 条
          </Typography.Text>
          <Button type="link" size="small" style={{ padding: 0 }} onClick={onClearSelection}>
            清空
          </Button>
        </Space>
      )}
      {tooltip && (
        <Tooltip title={tooltip} placement="left">
          <QuestionCircleOutlined
            aria-label="导出说明"
            style={{ color: 'rgba(0, 0, 0, 0.45)', cursor: 'help' }}
          />
        </Tooltip>
      )}
      <Dropdown
        trigger={['click']}
        placement="bottomRight"
        menu={{ items, onClick: handleMenuClick }}
      >
        <Button icon={<DownloadOutlined />}>
          {buttonLabel} <DownOutlined />
        </Button>
      </Dropdown>
    </Space>
  )
}
