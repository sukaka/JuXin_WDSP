import { Buffer } from 'buffer'

/**
 * mmdb-lib 在模块顶层即引用 Node 全局 Buffer（metadata.js 的 Buffer.from 等），
 * 浏览器环境需在任何 mmdb-lib 求值之前把 polyfill 挂到 globalThis。
 * 本模块必须作为首个 import（导入顺序即求值顺序）。
 */
const globalScope = globalThis as typeof globalThis & { Buffer?: typeof Buffer }
if (typeof globalScope.Buffer === 'undefined') {
  globalScope.Buffer = Buffer
}
