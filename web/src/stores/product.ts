import { create } from 'zustand'
import { productApi } from '../api/apiAssets'

export type ProductEdition = 'waf' | 'wdsp' | 'api'

interface ProductState {
  edition: ProductEdition
  apiDynamicProtection: boolean
  webWafEnabled: boolean
  /** APM 业务性能（无 Agent）能力开关；默认 false fail-safe */
  apmEnabled: boolean
  productName: string
  initialized: boolean
  load: () => Promise<void>
  reset: () => void
}

const SAFE_DEFAULTS = {
  edition: 'waf' as const,
  apiDynamicProtection: false,
  webWafEnabled: true,
  apmEnabled: false,
  productName: '九章WEB应用智能防护系统',
}

function normalizeEdition(raw: string | undefined): ProductEdition {
  if (raw === 'wdsp' || raw === 'api' || raw === 'waf') return raw
  return 'waf'
}

export const useProductStore = create<ProductState>()((set) => ({
  ...SAFE_DEFAULTS,
  initialized: false,
  load: async () => {
    try {
      const data = await productApi.edition()
      const edition = normalizeEdition(data.edition)
      const apiOn = data.api_dynamic_protection === true
      // API 动态防护仅 wdsp/api 可对外暴露（与后端 APIDynamicProtectionEnabled 一致）
      const apiDynamicProtection =
        (edition === 'wdsp' || edition === 'api') && apiOn
      const webWafEnabled =
        typeof data.web_waf_enabled === 'boolean' ? data.web_waf_enabled : edition !== 'api'
      // APM 为共享底座能力，不做 edition 门控；缺省/异常均按关闭处理（fail-safe）
      const apmEnabled = data.apm_enabled === true
      set({
        edition,
        apiDynamicProtection,
        webWafEnabled,
        apmEnabled,
        productName: data.product_name || SAFE_DEFAULTS.productName,
        initialized: true,
      })
    } catch {
      set({ ...SAFE_DEFAULTS, initialized: true })
    }
  },
  reset: () => set({ ...SAFE_DEFAULTS, initialized: false }),
}))
