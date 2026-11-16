import { request } from './client'

/**
 * 容器运维管理（containers.read / containers.logs / containers.control / containers.update）。
 * 后端契约（字段名冻结）：
 * - GET  /system/containers                         -> { containers: ContainerInfo[] }
 * - GET  /system/containers/{service}/logs          -> { service, lines, truncated, next_since }
 * - GET  /system/containers/actions/{job_id}        -> ContainerActionJob
 * - POST /system/containers/{service}/start|stop|restart|update -> 202 { job_id, status }
 * start/stop/restart 请求体 { password }；update 请求体 { password, confirmText }。
 */

/** 更新容器操作的固定确认文本（前后端约定一致） */
export const CONTAINER_UPDATE_CONFIRM_TEXT = '更新容器'

export interface ContainerInfo {
  service: string
  project: string
  id: string
  name: string
  image: string
  image_id: string
  state: string
  status: string
  health: string
  running: boolean
  restart_count: number
  started_at: string
}

export interface ContainerLogLine {
  timestamp: string
  stream: string
  message: string
}

export interface ContainerLogsResp {
  service: string
  lines: ContainerLogLine[]
  /** true 表示本次返回被截断（达到服务端条数/字节上限） */
  truncated: boolean
  /** 下一次增量拉取使用的 since（UNIX 秒） */
  next_since: number
}

export type ContainerActionKind = 'start' | 'stop' | 'restart' | 'update'

export interface ContainerActionJob {
  job_id: string
  service: string
  action: string
  /** PENDING / RUNNING / SUCCESS / FAILED */
  status: string
  message: string
  started_at: string
  finished_at: string
}

export interface ContainerActionAccepted {
  job_id: string
  status: string
}

export const containerOpsApi = {
  list: async () => {
    const data = await request<{ containers: ContainerInfo[] | null }>('/system/containers')
    return { containers: data.containers ?? [] }
  },
  /** 日志拉取：首屏传 tail；增量传 since（上次响应的 next_since），tail 作为条数上限 */
  logs: (service: string, params: { tail?: number; since?: number }) =>
    request<ContainerLogsResp>(`/system/containers/${encodeURIComponent(service)}/logs`, {
      query: { tail: params.tail, since: params.since },
    }),
  actionStatus: (jobId: string) =>
    request<ContainerActionJob>(`/system/containers/actions/${encodeURIComponent(jobId)}`),
  start: (service: string, password: string) =>
    request<ContainerActionAccepted>(`/system/containers/${encodeURIComponent(service)}/start`, {
      method: 'POST',
      body: { password },
    }),
  stop: (service: string, password: string) =>
    request<ContainerActionAccepted>(`/system/containers/${encodeURIComponent(service)}/stop`, {
      method: 'POST',
      body: { password },
    }),
  restart: (service: string, password: string) =>
    request<ContainerActionAccepted>(`/system/containers/${encodeURIComponent(service)}/restart`, {
      method: 'POST',
      body: { password },
    }),
  update: (service: string, password: string, confirmText: string) =>
    request<ContainerActionAccepted>(`/system/containers/${encodeURIComponent(service)}/update`, {
      method: 'POST',
      body: { password, confirmText },
    }),
}
