import { request } from './client'

/** 恢复出厂设置的确认文字（前后端约定一致） */
export const FACTORY_RESET_CONFIRM_TEXT = '恢复出厂'

/**
 * 系统控制（system.reboot / system.shutdown / system.factory_reset）。
 * 三个接口均为高风险操作，页面层必须先经密码确认弹窗二次确认；
 * 成功后系统即将不可用，不做任何自动刷新。
 */
export const systemOpsApi = {
  reboot: (password: string) =>
    request<{ message: string }>('/system/reboot', { method: 'POST', body: { password } }),
  shutdown: (password: string) =>
    request<{ message: string }>('/system/shutdown', { method: 'POST', body: { password } }),
  factoryReset: (password: string, confirmText: string) =>
    request<{ message: string }>('/system/factory-reset', { method: 'POST', body: { password, confirmText } }),
}
