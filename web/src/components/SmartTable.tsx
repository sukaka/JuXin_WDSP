import {
  isValidElement,
  useMemo,
  useRef,
  useState,
  type MouseEvent as ReactMouseEvent,
  type ReactNode,
} from 'react'
import { Button, Checkbox, Popover, Table } from 'antd'
import type { CheckboxChangeEvent } from 'antd/es/checkbox'
import type { TableProps } from 'antd'
import type { ColumnType } from 'antd/es/table'
import { SettingOutlined } from '@ant-design/icons'
import TableRefreshControl from './TableRefreshControl'

/**
 * SmartTable：全系统统一表格增强（不引入新依赖）。
 * - 列宽拖拽：表头右侧拖拽手柄调整列宽；
 * - 列显隐：右上角「列设置」勾选显示列；
 * - 刷新与自动刷新：右上角「刷新」按钮与自定义秒数「自动刷新」开关；
 * - 传入 storageKey 时，列宽、显隐与自动刷新间隔记忆到 localStorage（跨会话保持）。
 */

interface Persisted {
  w: Record<string, number>
  h: string[]
}

function loadPersisted(storageKey?: string, defaultHiddenKeys?: string[]): Persisted {
  const defaultHidden = defaultHiddenKeys ? [...defaultHiddenKeys] : []
  if (!storageKey) return { w: {}, h: defaultHidden }
  try {
    const raw = localStorage.getItem('smart-table:' + storageKey)
    if (!raw) return { w: {}, h: defaultHidden }
    const parsed = JSON.parse(raw) as Partial<Persisted>
    return {
      w: typeof parsed.w === 'object' && parsed.w !== null ? parsed.w : {},
      h: Array.isArray(parsed.h) ? parsed.h.filter((x) => typeof x === 'string') : defaultHidden,
    }
  } catch {
    return { w: {}, h: defaultHidden }
  }
}

function savePersisted(storageKey: string | undefined, p: Persisted) {
  if (!storageKey) return
  try {
    localStorage.setItem('smart-table:' + storageKey, JSON.stringify(p))
  } catch {
    // 存储不可用（隐私模式等）时仅保持会话内状态
  }
}

/** 表头拖拽手柄：mousedown 起拖，document 级 mousemove/mouseup 收尾 */
function ResizableTitle({
  children,
  width,
  onResize,
}: {
  children: ReactNode
  width?: number
  onResize: (w: number) => void
}) {
  const drag = useRef<{ x: number; w: number } | null>(null)
  const onMouseDown = (e: ReactMouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    const measured = e.currentTarget.closest('th')?.getBoundingClientRect().width
    const startWidth =
      typeof width === 'number' ? width : measured && measured > 0 ? Math.round(measured) : 120
    drag.current = { x: e.clientX, w: startWidth }
    const move = (ev: MouseEvent) => {
      if (!drag.current) return
      onResize(Math.max(60, drag.current.w + ev.clientX - drag.current.x))
    }
    const up = () => {
      drag.current = null
      document.removeEventListener('mousemove', move)
      document.removeEventListener('mouseup', up)
    }
    document.addEventListener('mousemove', move)
    document.addEventListener('mouseup', up)
  }
  return (
    <span style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 4 }}>
      <span style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{children}</span>
      <span
        role="separator"
        aria-label="拖拽调整列宽"
        onMouseDown={onMouseDown}
        onClick={(e) => e.stopPropagation()}
        style={{ cursor: 'col-resize', color: '#c0c4cc', userSelect: 'none', flexShrink: 0, letterSpacing: -2 }}
      >
        ⋮⋮
      </span>
    </span>
  )
}

export interface SmartTableProps<T extends object> extends Omit<TableProps<T>, 'columns' | 'components'> {
  columns: TableProps<T>['columns']
  components?: TableProps<T>['components']
  /** 持久化键（smart-table:<key>）；不传则仅会话内有效 */
  storageKey?: string
  /** 首次访问（尚无本地持久化记录）与重置时默认隐藏的列 key 列表 */
  defaultHiddenKeys?: string[]
  /** 自定义刷新回调；未传时默认刷新当前页活跃查询 */
  onRefresh?: () => void | Promise<unknown>
  /** 仅刷新指定 queryKey 前缀（未传 onRefresh 时生效） */
  refreshQueryKeys?: readonly (readonly unknown[])[]
  /** 隐藏右上角刷新与自动刷新控件（默认显示） */
  hideRefresh?: boolean
  /** 自动刷新默认间隔秒数（默认 10 秒） */
  defaultRefreshIntervalSeconds?: number
}

/** 递归提取 ReactNode 中的可读文本，避免列设置中 JSX 表头回退为原始英文 key/dataIndex */
export function extractNodeText(node: ReactNode): string {
  if (node === null || node === undefined || typeof node === 'boolean') return ''
  if (typeof node === 'string' || typeof node === 'number') return String(node)
  if (Array.isArray(node)) {
    return node
      .map((child) => extractNodeText(child))
      .filter(Boolean)
      .join(' ')
      .replace(/\s+/g, ' ')
      .trim()
  }
  if (isValidElement<{ children?: ReactNode }>(node)) {
    return extractNodeText(node.props?.children)
  }
  return ''
}

function colKeyOf<T>(c: ColumnType<T>, index: number): string {
  const k = c.key ?? c.dataIndex
  return typeof k === 'string' || typeof k === 'number' ? String(k) : String(index)
}

export default function SmartTable<T extends object>(props: SmartTableProps<T>) {
  const {
    columns = [],
    storageKey,
    defaultHiddenKeys,
    components,
    onRefresh,
    refreshQueryKeys,
    hideRefresh = false,
    defaultRefreshIntervalSeconds,
    scroll,
    ...rest
  } = props
  const isTableLoading =
    typeof rest.loading === 'boolean' ? rest.loading : Boolean(rest.loading?.spinning)
  const [persisted] = useState<Persisted>(() => loadPersisted(storageKey, defaultHiddenKeys))
  const [widths, setWidths] = useState<Record<string, number>>(persisted.w)
  const [hidden, setHidden] = useState<string[]>(persisted.h)

  const persist = (w: Record<string, number>, h: string[]) => savePersisted(storageKey, { w, h })

  const setWidth = (key: string, w: number) => {
    setWidths((prev) => {
      const next = { ...prev, [key]: w }
      persist(next, hidden)
      return next
    })
  }

  const toggleColumn = (key: string, visible: boolean) => {
    setHidden((prev) => {
      const next = visible ? prev.filter((k) => k !== key) : [...prev, key]
      persist(widths, next)
      return next
    })
  }

  const resetAll = () => {
    const defaultHidden = defaultHiddenKeys ? [...defaultHiddenKeys] : []
    setWidths({})
    setHidden(defaultHidden)
    persist({}, defaultHidden)
  }

  const mergedColumns = useMemo(() => {
    return columns
      .map((c, i) => ({ c, key: colKeyOf(c, i) }))
      .filter(({ key }) => !hidden.includes(key))
      .map(({ c, key }) => {
        const width = widths[key] ?? c.width
        return {
          ...c,
          width,
          title: (
            <ResizableTitle width={typeof width === 'number' ? width : undefined} onResize={(w) => setWidth(key, w)}>
              {c.title as ReactNode}
            </ResizableTitle>
          ),
        }
      })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [columns, hidden, widths])

  const mergedScroll = useMemo(() => {
    if (!scroll || typeof scroll.x !== 'number' || Object.keys(widths).length === 0) {
      return scroll
    }
    const totalWidth = mergedColumns.reduce(
      (sum, c) => sum + (typeof c.width === 'number' ? c.width : 120),
      0,
    )
    return totalWidth > scroll.x ? { ...scroll, x: totalWidth } : scroll
  }, [scroll, mergedColumns, widths])

  const settingsContent = (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 320, overflow: 'auto' }}>
      {columns.map((c, i) => {
        const key = colKeyOf(c, i)
        const titleNode = typeof c.title === 'function' ? undefined : (c.title as ReactNode)
        const label = extractNodeText(titleNode) || key
        return (
          <Checkbox
            key={key}
            checked={!hidden.includes(key)}
            onChange={(e: CheckboxChangeEvent) => toggleColumn(key, e.target.checked)}
          >
            {label}
          </Checkbox>
        )
      })}
      <Button size="small" style={{ marginTop: 4 }} onClick={resetAll}>
        重置列宽与显隐
      </Button>
    </div>
  )

  return (
    <div>
      <div
        style={{
          display: 'flex',
          justifyContent: 'flex-end',
          alignItems: 'center',
          gap: 8,
          flexWrap: 'wrap',
          marginBottom: 4,
        }}
      >
        {!hideRefresh && (
          <TableRefreshControl
            onRefresh={onRefresh}
            refreshQueryKeys={refreshQueryKeys}
            storageKey={storageKey}
            defaultIntervalSeconds={defaultRefreshIntervalSeconds}
            loading={isTableLoading}
          />
        )}
        <Popover content={settingsContent} trigger="click" placement="bottomRight" title="列设置">
          <Button size="small" type="text" icon={<SettingOutlined />} aria-label="列设置" />
        </Popover>
      </div>
      <Table<T> columns={mergedColumns} components={components} scroll={mergedScroll} {...rest} />
    </div>
  )
}
