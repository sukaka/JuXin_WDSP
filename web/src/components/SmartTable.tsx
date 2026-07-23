import { useMemo, useRef, useState, type MouseEvent as ReactMouseEvent, type ReactNode } from 'react'
import { Button, Checkbox, Popover, Table } from 'antd'
import type { CheckboxChangeEvent } from 'antd/es/checkbox'
import type { TableProps } from 'antd'
import type { ColumnType } from 'antd/es/table'
import { SettingOutlined } from '@ant-design/icons'

/**
 * SmartTable：全系统统一表格增强（不引入新依赖）。
 * - 列宽拖拽：表头右侧拖拽手柄调整列宽；
 * - 列显隐：右上角「列设置」勾选显示列；
 * - 传入 storageKey 时，列宽与显隐记忆到 localStorage（跨会话保持）。
 */

interface Persisted {
  w: Record<string, number>
  h: string[]
}

function loadPersisted(storageKey?: string): Persisted {
  if (!storageKey) return { w: {}, h: [] }
  try {
    const raw = localStorage.getItem('smart-table:' + storageKey)
    if (!raw) return { w: {}, h: [] }
    const parsed = JSON.parse(raw) as Partial<Persisted>
    return {
      w: typeof parsed.w === 'object' && parsed.w !== null ? parsed.w : {},
      h: Array.isArray(parsed.h) ? parsed.h.filter((x) => typeof x === 'string') : [],
    }
  } catch {
    return { w: {}, h: [] }
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
  width: number
  onResize: (w: number) => void
}) {
  const drag = useRef<{ x: number; w: number } | null>(null)
  const onMouseDown = (e: ReactMouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    drag.current = { x: e.clientX, w: width }
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
}

function colKeyOf<T>(c: ColumnType<T>, index: number): string {
  const k = c.key ?? c.dataIndex
  return typeof k === 'string' || typeof k === 'number' ? String(k) : String(index)
}

export default function SmartTable<T extends object>(props: SmartTableProps<T>) {
  const { columns = [], storageKey, components, ...rest } = props
  const [persisted] = useState<Persisted>(() => loadPersisted(storageKey))
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
    setWidths({})
    setHidden([])
    persist({}, [])
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
            <ResizableTitle width={typeof width === 'number' ? width : 120} onResize={(w) => setWidth(key, w)}>
              {c.title as ReactNode}
            </ResizableTitle>
          ),
        }
      })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [columns, hidden, widths])

  const settingsContent = (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 320, overflow: 'auto' }}>
      {columns.map((c, i) => {
        const key = colKeyOf(c, i)
        const label = typeof c.title === 'string' || typeof c.title === 'number' ? String(c.title) : key
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
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 4 }}>
        <Popover content={settingsContent} trigger="click" placement="bottomRight" title="列设置">
          <Button size="small" type="text" icon={<SettingOutlined />} aria-label="列设置" />
        </Popover>
      </div>
      <Table<T> columns={mergedColumns} components={components} {...rest} />
    </div>
  )
}
