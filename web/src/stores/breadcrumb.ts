import { useEffect } from 'react'
import { create } from 'zustand'

interface BreadcrumbStoreState {
  /** 详情页注入的当前对象名称（面包屑末级）；null = 无对象层级 */
  objectName: string | null
  setObjectName: (objectName: string | null) => void
}

export const useBreadcrumbStore = create<BreadcrumbStoreState>()((set) => ({
  objectName: null,
  setObjectName: (objectName) => set({ objectName }),
}))

/** 详情页注入面包屑对象名；名称变化自动更新，组件卸载时自动清理 */
export function useBreadcrumbObjectName(name: string | null | undefined) {
  const setObjectName = useBreadcrumbStore((s) => s.setObjectName)
  useEffect(() => {
    setObjectName(name ?? null)
    return () => setObjectName(null)
  }, [name, setObjectName])
}
