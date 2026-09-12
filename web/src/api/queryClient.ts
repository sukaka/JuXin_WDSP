import { QueryClient } from '@tanstack/react-query'

/** 全局 QueryClient 单例：App Provider 与登出/会话失效清理共用。
 * 主动登出（SPA 跳转不刷新页面）必须 clear()，否则共享浏览器跨账号残留上一账号的缓存数据 */
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, refetchOnWindowFocus: false, staleTime: 10_000 },
  },
})
