import { describe, expect, it } from 'vitest'
import { API_FINDING_TYPE_META } from '../stage8'

describe('群控 Finding 展示元数据', () => {
  it('同设备多账号使用可读中文标签', () => {
    expect(API_FINDING_TYPE_META.SHARED_DEVICE_ACCOUNTS).toEqual({
      color: 'orange',
      label: '同设备多账号',
    })
  })
})
