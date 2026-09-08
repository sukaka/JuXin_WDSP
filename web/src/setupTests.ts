import '@testing-library/jest-dom/vitest'
import { configure } from '@testing-library/react'

// 慢速/高负载开发机上 antd Drawer/Modal 渲染常超 testing-library 默认 1s 异步等待，
// 全局放宽到 10s——只放大等待窗口，不放宽任何断言（失败用例会真实等到超时再报）
configure({ asyncUtilTimeout: 10000 })

// jsdom 缺少的浏览器 API polyfill（antd 组件依赖）
if (!window.matchMedia) {
  window.matchMedia = ((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  })) as unknown as typeof window.matchMedia
}

if (!window.ResizeObserver) {
  window.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  } as unknown as typeof window.ResizeObserver
}
