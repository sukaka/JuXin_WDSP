import { create } from 'zustand'
import { productApi } from '../api/apiAssets'

export type ProductEdition = 'waf' | 'wdsp'

interface ProductState {
  edition: ProductEdition
  apiDynamicProtection: boolean
  initialized: boolean
  load: () => Promise<void>
  reset: () => void
}

const SAFE_DEFAULTS = {
  edition: 'waf' as const,
  apiDynamicProtection: false,
}

export const useProductStore = create<ProductState>()((set) => ({
  ...SAFE_DEFAULTS,
  initialized: false,
  load: async () => {
    try {
      const data = await productApi.edition()
      const edition: ProductEdition = data.edition === 'wdsp' ? 'wdsp' : 'waf'
      set({
        edition,
        apiDynamicProtection: edition === 'wdsp' && data.api_dynamic_protection === true,
        initialized: true,
      })
    } catch {
      set({ ...SAFE_DEFAULTS, initialized: true })
    }
  },
  reset: () => set({ ...SAFE_DEFAULTS, initialized: false }),
}))
