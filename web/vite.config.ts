import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { loadEnv, type Plugin } from 'vite'

const clayglExprPath = fileURLToPath(new URL('./src/utils/clayglExpr.ts', import.meta.url))
const CLAYGL_TRY_CONVERT_EXPR_RE =
  /function tryConvertExpr\(string\)\s*\{[\s\S]*?new Function\('width',\s*'height',\s*'dpr',\s*'return '\s*\+\s*exprRes\[1\]\)[\s\S]*?throw new Error\('Invalid expression\.'\);\s*\}\s*\}\s*\}/

function patchClayglCreateCompositor(code: string): string {
  if (!CLAYGL_TRY_CONVERT_EXPR_RE.test(code)) {
    throw new Error(
      'clayglCspSafePlugin: unable to locate tryConvertExpr(new Function) in claygl/src/createCompositor.js',
    )
  }
  const importStmt = `import { compileClayglExpr as tryConvertExpr } from ${JSON.stringify(clayglExprPath)};\n`
  return importStmt + code.replace(CLAYGL_TRY_CONVERT_EXPR_RE, '')
}

/**
 * 消除 claygl/src/createCompositor.js 中依赖 unsafe-eval 的 `new Function`，
 * 使 3D 攻击态势地球大屏在严格 CSP（script-src 'self'）下正常运行。
 */
function clayglCspSafePlugin(): Plugin {
  return {
    name: 'claygl-csp-safe-expr',
    enforce: 'pre',
    transform(code, id) {
      const normalized = id.replace(/\\/g, '/')
      if (!normalized.endsWith('/claygl/src/createCompositor.js')) {
        return null
      }
      return {
        code: patchClayglCreateCompositor(code),
        map: null,
      }
    },
  }
}

// 版本号构建期注入：package.json version 为唯一来源（发版递增它即可），
// 避免 constants 硬编码与发版流程脱节；tsconfig.node 未开 resolveJsonModule，故用 fs 读取
const appVersion =
  (JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf-8')) as { version?: string })
    .version ?? '0.0.0'

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '.', '')

  return {
    plugins: [clayglCspSafePlugin(), react()],
    optimizeDeps: {
      esbuildOptions: {
        plugins: [
          {
            name: 'claygl-csp-safe-expr-esbuild',
            setup(build) {
              build.onLoad({ filter: /[\\/]claygl[\\/]src[\\/]createCompositor\.js$/ }, (args) => {
                const raw = readFileSync(args.path, 'utf-8')
                return {
                  contents: patchClayglCreateCompositor(raw),
                  loader: 'js',
                }
              })
            },
          },
        ],
      },
    },
    define: {
      __APP_VERSION__: JSON.stringify(appVersion),
    },
    build: {
      // 生产交付不携带独立或内联 source map；最终产物仍由离线交付扫描器复核。
      sourcemap: false,
      rollupOptions: {
        output: {
          manualChunks(id) {
            if (
              id.includes('/node_modules/react/') ||
              id.includes('/node_modules/react-dom/') ||
              id.includes('/node_modules/scheduler/')
            ) {
              return 'vendor-react'
            }
          },
        },
      },
    },
    server: {
      port: 5173,
      proxy: {
        // 仅代理 /api/v1（不能写 '/api'：会与阶段8 页面路由 /api-endpoints 等冲突，
        // 导致整页刷新被代理到后端返回 404）
        '/api/v1': {
          target: env.VITE_API_PROXY || 'http://localhost:18081',
          // 保持原始 Host（localhost:5173），使 CSRF Origin 校验通过（与生产同域部署一致）
          changeOrigin: false,
        },
      },
    },
    test: {
      environment: 'jsdom',
      setupFiles: './src/setupTests.ts',
      globals: true,
      // setupTests.ts 已把异步等待放宽到 10s（慢速/高负载开发机 antd 渲染慢），
      // 默认 5s 的 testTimeout 比它还短，全量并行时大量用例仅因超时被误杀；
      // 放宽到 20s 只放大用例整体时间上限，不放宽任何断言
      testTimeout: 20000,
      // jsdom + antd 页面测试是 CPU/内存密集型，默认 workers=核数-1 会造成抢占抖动
      // （实测 10 核/16GB 机器 9 个 worker 下单用例从 6-8s 劣化到 20s+）；
      // 固定 4 个 worker 全量墙钟时间基本持平，稳定性显著提升
      maxWorkers: 4,
      // 排除 Playwright E2E 用例（由 npx playwright test 单独运行）
      exclude: ['**/node_modules/**', '**/dist/**', 'e2e/**'],
    },
  }
})
