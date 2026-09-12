import '@testing-library/jest-dom/vitest'
import { configure } from '@testing-library/react'

// 慢速/高负载开发机上 antd Drawer/Modal 渲染常超 testing-library 默认 1s 异步等待，
// 全局放宽到 10s——只放大等待窗口，不放宽任何断言（失败用例会真实等到超时再报）
configure({ asyncUtilTimeout: 10000 })

// jsdom 会在传入伪元素参数时输出“Not implemented”并返回普通样式；antd
// 的滚动条测量会频繁触发该路径。测试环境忽略伪元素参数即可复现浏览器中
// 本次组件所需的布局读取行为，同时避免大量异常日志拖慢页面测试。
const getComputedStyle = window.getComputedStyle.bind(window)
window.getComputedStyle = ((element: Element) => getComputedStyle(element)) as typeof window.getComputedStyle

// 部分 Node 版本会暴露未配置存储文件的实验性 localStorage，此时对象存在但
// 不实现标准 Storage 方法。仅在 API 不完整时用内存实现，避免覆盖 jsdom 正常实现。
if (typeof globalThis.localStorage?.clear !== 'function') {
  const values = new Map<string, string>()
  const localStorage: Storage = {
    get length() {
      return values.size
    },
    clear: () => values.clear(),
    getItem: (key) => values.get(key) ?? null,
    key: (index) => Array.from(values.keys())[index] ?? null,
    removeItem: (key) => values.delete(key),
    setItem: (key, value) => values.set(key, String(value)),
  }
  Object.defineProperty(globalThis, 'localStorage', {
    configurable: true,
    value: localStorage,
  })
}

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
