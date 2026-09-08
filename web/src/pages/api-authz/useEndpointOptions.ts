import { useQuery } from '@tanstack/react-query'
import { apiEndpointsApi } from '../../api/apiAssets'

/** 端点选项查询（三 Tab 与评估卡片共用同一 queryKey，TanStack Query 自动去重；取前 100 条资产） */
export function useEndpointOptions() {
  const query = useQuery({
    queryKey: ['api-authz', 'endpoint-options'],
    queryFn: () => apiEndpointsApi.list({ page: 1, page_size: 100 }),
  })
  const options = (query.data?.items ?? []).map((e) => ({ value: e.id, label: e.endpoint_key }))
  /** endpoint_id → 「METHOD 路径模板」展示名（选项未覆盖时返回 undefined，调用方回退为 id） */
  const labelOf = (id: string) => options.find((o) => o.value === id)?.label
  return { ...query, options, labelOf }
}
