import { test, expect } from '@playwright/test'
import { loginViaAPI, API_URL } from './helpers'
import { dataFlowDepths } from '../src/utils/dataFlowCharts'

const username = process.env.E2E_SEC_USER || ''
const password = process.env.E2E_SEC_PWD || ''
const applicationID = process.env.WDSP_DATA_FLOW_APPLICATION_ID || ''
const applicationName =
  process.env.WDSP_DATA_FLOW_APPLICATION_NAME || 'Cloud Dataflow Test'

test('真实业务观测形成 A→B、B→C、A→C 系统 API 敏感数据流向', async ({
  page,
}) => {
  test.skip(
    !username || !password || !applicationID,
    '由 TestCloudAPIDataFlowEndToEnd 提供真实环境和测试身份',
  )
  const pageErrors: string[] = []
  page.on('pageerror', (error) => pageErrors.push(error.message))

  await loginViaAPI(page, username, password)
  const graphResponse = await page.request.get(
    `${API_URL}/api-security/data-flow/graph?application_id=${applicationID}`,
  )
  expect(graphResponse.status()).toBe(200)
  const graphBody = await graphResponse.text()
  expect(graphBody).not.toContain('body_base64')
  expect(graphBody).not.toContain('13800138000')
  const graph = JSON.parse(graphBody).data
  const hasRelation = (source: string, target: string) =>
    graph.edges.some(
      (edge: { source_name: string; target_name: string }) =>
        edge.source_name === source && edge.target_name === target,
    )
  expect(hasRelation('orders', 'profile')).toBe(true)
  expect(hasRelation('profile', 'identity')).toBe(true)
  expect(hasRelation('orders', 'identity')).toBe(true)
  expect(graph.edges).toHaveLength(3)
  expect(graphBody).not.toContain('kafka/customer-events')

  await page.goto('/api-data-flow')
  await expect(page.locator('.ant-card-head')).toContainText('数据流向')
  await page.getByRole('combobox', { name: '应用', exact: true }).click()
  await page
    .locator('.ant-select-dropdown:visible .ant-select-item-option')
    .filter({ hasText: applicationName })
    .click()
  await page.getByRole('button', { name: /查\s*询/ }).click()
  await expect(
    page.getByRole('button', { name: 'orders · 2 次', exact: true }),
  ).toBeVisible()
  const flowRegion = page.getByRole('region', {
    name: '应用数据流向图',
    exact: true,
  })
  await expect(flowRegion).toBeVisible()

  const canvas = flowRegion.locator('canvas').first()
  const depths = dataFlowDepths(graph.nodes, graph.edges)
  const ordersPoint = await page.evaluate(
    async (depth) => {
      const root = document.querySelector(
        '.data-flow-canvas [_echarts_instance_]',
      )
      if (!root) throw new Error('ECharts root not found')
      const modulePath = '/node_modules/.vite/deps/echarts_core.js'
      const { getInstanceByDom } = await import(modulePath)
      const chart = getInstanceByDom(root)
      if (!chart) throw new Error('ECharts instance not found')
      const point = chart.convertToPixel({ xAxisIndex: 0, yAxisIndex: 0 }, [
        depth * 324,
        0,
      ]) as number[]
      const element = root.querySelector('canvas')
      if (!element) throw new Error('canvas not found')
      const rect = element.getBoundingClientRect()
      return { x: rect.left + point[0], y: rect.top + point[1] }
    },
    depths.get('service:orders') ?? 0,
  )
  const ordersX = ordersPoint.x
  const ordersY = ordersPoint.y
  await page.mouse.click(ordersX, ordersY)
  const nodeDrawer = page.getByRole('dialog', {
    name: 'orders · 系统详情',
    exact: true,
  })
  await expect(nodeDrawer).toContainText('orders → profile（1 次）')
  await nodeDrawer.locator('.ant-drawer-close').click()
  await expect(nodeDrawer).toBeHidden()
  await expect(page.locator('.ant-drawer-mask:visible')).toHaveCount(0)

  const beforeDrag = await canvas.evaluate((element) =>
    (element as HTMLCanvasElement).toDataURL(),
  )
  await page.mouse.move(ordersX, ordersY)
  await page.mouse.down()
  await page.mouse.move(ordersX + 48, ordersY + 32, { steps: 5 })
  await page.mouse.up()
  expect(pageErrors).toEqual([])
  await expect
    .poll(async () =>
      page.evaluate(async () => {
        const root = document.querySelector(
          '.data-flow-canvas [_echarts_instance_]',
        )
        if (!root) return []
        const modulePath = '/node_modules/.vite/deps/echarts_core.js'
        const { getInstanceByDom } = await import(modulePath)
        const option = getInstanceByDom(root)?.getOption() as {
          series?: Array<{
            id?: string
            data?: Array<{ id?: string; value?: number[] }>
          }>
        }
        return (
          option?.series
            ?.find((item) => item.id === 'dataflow-nodes')
            ?.data?.find((item) => item.id === 'service:orders')?.value ?? []
        )
      }),
    )
    .not.toEqual([depths.get('service:orders')! * 324, 0])
  await expect
    .poll(() =>
      canvas.evaluate((element) => (element as HTMLCanvasElement).toDataURL()),
    )
    .not.toBe(beforeDrag)

  await page.getByRole('button', { name: 'orders · 2 次', exact: true }).click()
  await expect(nodeDrawer).toContainText('orders → profile（1 次）')
  await expect(nodeDrawer).toContainText('orders → identity（1 次）')
  await nodeDrawer.locator('.ant-drawer-close').click()

  await page
    .locator('.ant-radio-button-wrapper')
    .filter({ hasText: '边明细' })
    .click()
  const callRow = page
    .locator('tbody tr')
    .filter({ hasText: 'POST /profiles/{id}' })
  await expect(callRow).toContainText('POST /profiles/{id}')
  await expect(callRow).toContainText('手机号')
  await expect(callRow).toContainText('身份证号')
  await callRow.getByRole('button', { name: '查看详情' }).click()
  const evidenceDrawer = page.getByRole('dialog', {
    name: 'orders → profile',
    exact: true,
  })
  await expect(evidenceDrawer).toContainText('$.mobile')
  await expect(evidenceDrawer).toContainText('$.identity_no')
  await expect(evidenceDrawer).toContainText('响应：profile → orders')
  await expect(evidenceDrawer).toContainText('CORRELATED_FIELD')
  await expect(evidenceDrawer).toContainText(`Trace: ${'a'.repeat(32)}`)
  await expect(evidenceDrawer).not.toContainText('13800138000')
  await expect(evidenceDrawer).not.toContainText('body_base64')
  await evidenceDrawer.locator('.ant-drawer-close').click()
  await expect(evidenceDrawer).toBeHidden()
  await expect(page.locator('.ant-drawer-mask:visible')).toHaveCount(0)

  const boundaryResponse = await page.request.get(
    `${API_URL}/api-security/data-flow/graph?application_id=${applicationID}&view=boundary`,
  )
  expect(boundaryResponse.status()).toBe(200)
  const boundaryBody = await boundaryResponse.text()
  expect(boundaryBody).not.toContain('body_base64')
  expect(boundaryBody).not.toContain('13800138000')
  const boundaryGraph = JSON.parse(boundaryBody).data
  expect(boundaryGraph.view).toBe('boundary')
  expect(boundaryGraph.edges).toHaveLength(2)
  type BoundaryEdge = {
    id: string
    source_id: string
    target_id: string
    source_name: string
    target_name: string
    source_zone: string
    target_zone: string
    boundary_type: string
    boundary_evidence: string
    calls: number
  }
  const boundaryEdges = boundaryGraph.edges as BoundaryEdge[]
  const publicEdge = boundaryEdges.find(
    (edge) => edge.source_name === '8.8.8.8',
  )
  const unknownEdge = boundaryEdges.find(
    (edge) => edge.source_name === '1.1.1.1',
  )
  if (!publicEdge || !unknownEdge) throw new Error('内外网边界缺少预期来源')
  expect(publicEdge).toMatchObject({
    source_id: 'client:8.8.8.8',
    target_id: 'service:profile',
    target_name: 'profile',
    source_zone: 'PUBLIC',
    target_zone: 'INTERNAL',
    boundary_type: 'PUBLIC_TO_INTERNAL',
    boundary_evidence: 'DIRECT_PEER',
    calls: 1,
  })
  expect(unknownEdge).toMatchObject({
    source_id: 'client:1.1.1.1',
    target_id: 'service:profile',
    target_name: 'profile',
    source_zone: 'UNKNOWN',
    target_zone: 'INTERNAL',
    boundary_type: 'UNKNOWN',
    boundary_evidence: 'UNTRUSTED_CLIENT_SOURCE',
    calls: 1,
  })

  const publicEvidenceResponse = await page.request.get(
    `${API_URL}/api-security/data-flow/evidence?application_id=${applicationID}&view=boundary&edge_id=${publicEdge.id}`,
  )
  expect(publicEvidenceResponse.status()).toBe(200)
  const publicEvidence = JSON.parse(await publicEvidenceResponse.text()).data
    .items
  expect(publicEvidence).toHaveLength(1)
  expect(publicEvidence[0]).toMatchObject({
    event_id: 'ev-cloud-boundary-public',
    service_name: 'profile',
    peer_address: '8.8.8.8',
    client_address: '8.8.8.8',
    client_address_source: 'DIRECT_PEER',
    server_address: '10.20.0.30',
    source_zone: 'PUBLIC',
    target_zone: 'INTERNAL',
    boundary_type: 'PUBLIC_TO_INTERNAL',
    boundary_evidence: 'DIRECT_PEER',
  })
  expect(publicEvidence[0].fields).toEqual([
    expect.objectContaining({
      side: 'REQUEST',
      path: '$.mobile',
      data_type: 'PHONE',
      value_hmac: `hmac-sha256:${'d'.repeat(64)}`,
    }),
  ])

  const unknownEvidenceResponse = await page.request.get(
    `${API_URL}/api-security/data-flow/evidence?application_id=${applicationID}&view=boundary&edge_id=${unknownEdge.id}`,
  )
  expect(unknownEvidenceResponse.status()).toBe(200)
  const unknownEvidence = JSON.parse(await unknownEvidenceResponse.text()).data
    .items
  expect(unknownEvidence).toHaveLength(1)
  expect(unknownEvidence[0]).toMatchObject({
    event_id: 'ev-cloud-boundary-unknown',
    service_name: 'profile',
    peer_address: '1.1.1.1',
    client_address: '1.1.1.1',
    client_address_source: 'UNKNOWN',
    server_address: '10.20.0.30',
    source_zone: 'UNKNOWN',
    target_zone: 'INTERNAL',
    boundary_type: 'UNKNOWN',
    boundary_evidence: 'UNTRUSTED_CLIENT_SOURCE',
  })

  await page
    .locator('.ant-radio-button-wrapper')
    .filter({ hasText: '应用流向' })
    .click()
  await page.getByRole('combobox', { name: '拓扑视图', exact: true }).click()
  await page
    .locator('.ant-select-dropdown:visible .ant-select-item-option')
    .filter({ hasText: '内外网边界' })
    .click()
  const boundaryUIResponse = page.waitForResponse(
    (response) =>
      response.url().includes('/api-security/data-flow/graph?') &&
      response.url().includes('view=boundary') &&
      response.status() === 200,
  )
  await page.getByRole('button', { name: /查\s*询/ }).click()
  await boundaryUIResponse
  const boundaryRegion = page.getByRole('region', {
    name: '内外网边界调用图',
    exact: true,
  })
  await expect(boundaryRegion).toBeVisible()
  await expect(boundaryRegion).toContainText('内外网边界')

  await page
    .getByRole('button', { name: '8.8.8.8 · 1 次', exact: true })
    .click()
  const publicNodeDrawer = page.getByRole('dialog', {
    name: '8.8.8.8 · 系统详情',
    exact: true,
  })
  await expect(publicNodeDrawer).toContainText('公网')
  await expect(publicNodeDrawer).toContainText('8.8.8.8 → profile（1 次）')
  await publicNodeDrawer
    .getByRole('button', { name: 'API 与字段', exact: true })
    .click()
  const publicEvidenceDrawer = page.getByRole('dialog', {
    name: '8.8.8.8 → profile',
    exact: true,
  })
  await expect(publicEvidenceDrawer).toContainText(
    '公网 → 内网 · PUBLIC_TO_INTERNAL',
  )
  await expect(publicEvidenceDrawer).toContainText('DIRECT_PEER')
  const publicAddressEvidence = publicEvidenceDrawer.locator(
    '[aria-label="边界地址证据"]',
  )
  await expect(publicAddressEvidence).toContainText('client_address')
  await expect(publicAddressEvidence).toContainText('peer_address')
  await expect(publicAddressEvidence).toContainText('server_address')
  await expect(publicAddressEvidence).toContainText('client_address_source')
  await expect(publicAddressEvidence).toContainText('8.8.8.8')
  await expect(publicAddressEvidence).toContainText('10.20.0.30')
  await expect(publicEvidenceDrawer).toContainText('$.mobile')
  await expect(publicEvidenceDrawer).toContainText(`Trace: ${'d'.repeat(32)}`)
  await expect(publicEvidenceDrawer).not.toContainText('13800138000')
  await expect(publicEvidenceDrawer).not.toContainText('body_base64')
  await publicEvidenceDrawer.locator('.ant-drawer-close').click()
  await expect(publicEvidenceDrawer).toBeHidden()
  await expect(page.locator('.ant-drawer-mask:visible')).toHaveCount(0)

  await page
    .getByRole('button', { name: '1.1.1.1 · 1 次', exact: true })
    .click()
  const unknownNodeDrawer = page.getByRole('dialog', {
    name: '1.1.1.1 · 系统详情',
    exact: true,
  })
  await expect(unknownNodeDrawer).toContainText('未知')
  await expect(unknownNodeDrawer).toContainText('1.1.1.1 → profile（1 次）')
  await unknownNodeDrawer
    .getByRole('button', { name: 'API 与字段', exact: true })
    .click()
  const unknownEvidenceDrawer = page.getByRole('dialog', {
    name: '1.1.1.1 → profile',
    exact: true,
  })
  await expect(unknownEvidenceDrawer).toContainText('边界未知 · UNKNOWN')
  await expect(unknownEvidenceDrawer).toContainText('UNTRUSTED_CLIENT_SOURCE')
  await expect(unknownEvidenceDrawer).not.toContainText('公网 → 内网')
  const unknownAddressEvidence = unknownEvidenceDrawer.locator(
    '[aria-label="边界地址证据"]',
  )
  await expect(unknownAddressEvidence).toContainText('client_address_source')
  await expect(unknownAddressEvidence).toContainText('UNKNOWN')
  await expect(unknownAddressEvidence).toContainText('1.1.1.1')
  await expect(unknownAddressEvidence).toContainText('10.20.0.30')
  await unknownEvidenceDrawer.locator('.ant-drawer-close').click()
  await expect(unknownEvidenceDrawer).toBeHidden()
  expect(pageErrors).toEqual([])
})
