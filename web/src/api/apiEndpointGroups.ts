import { request } from './client'
import type { ApiEndpointItem } from './apiAssets'
import type { PageResult } from '../types'

const ENDPOINT_GROUPS_PATH = '/api-security/endpoint-groups'

export const API_ENDPOINT_GROUP_CODE_PATTERN = /^[A-Z][A-Z0-9_]*$/

export interface ApiEndpointGroup {
  id: string
  application_id: string
  application_name: string
  code: string
  name: string
  description: string
  enabled: boolean
  endpoint_count: number
  created_at: string
  updated_at: string
}

export interface ApiEndpointGroupListParams {
  application_id?: string
  page: number
  page_size: number
}

export interface ApiEndpointGroupCreateInput {
  application_id: string
  code: string
  name: string
  description: string
  enabled: boolean
}

export interface ApiEndpointGroupUpdateInput {
  code: string
  name: string
  description: string
  enabled: boolean
}

export type ApiEndpoint = Pick<
  ApiEndpointItem,
  | 'id'
  | 'application_id'
  | 'http_method'
  | 'normalized_path'
  | 'endpoint_key'
  | 'asset_status'
> & {
  added_at: string
}

export interface ApiEndpointGroupMember {
  group_id: string
  endpoint_id: string
  created_at: string
}

export function normalizeApiEndpointGroupCode(value: string): string {
  return value.trim().toUpperCase()
}

export function toApiEndpointGroupUpdateInput(
  group: ApiEndpointGroup,
  overrides: Partial<ApiEndpointGroupUpdateInput> = {},
): ApiEndpointGroupUpdateInput {
  return {
    code: group.code,
    name: group.name,
    description: group.description,
    enabled: group.enabled,
    ...overrides,
  }
}

export const apiEndpointGroupsApi = {
  list: async (params: ApiEndpointGroupListParams) => {
    const data = await request<PageResult<ApiEndpointGroup>>(
      ENDPOINT_GROUPS_PATH,
      { query: { ...params } },
    )
    return { ...data, items: data.items ?? [] }
  },
  get: (id: string) =>
    request<ApiEndpointGroup>(`${ENDPOINT_GROUPS_PATH}/${id}`),
  create: (body: ApiEndpointGroupCreateInput) =>
    request<ApiEndpointGroup>(ENDPOINT_GROUPS_PATH, {
      method: 'POST',
      body,
    }),
  update: (id: string, body: ApiEndpointGroupUpdateInput) =>
    request<ApiEndpointGroup>(`${ENDPOINT_GROUPS_PATH}/${id}`, {
      method: 'PUT',
      body,
    }),
  remove: (id: string) =>
    request<{ status: string }>(`${ENDPOINT_GROUPS_PATH}/${id}`, {
      method: 'DELETE',
    }),
  listEndpoints: async (
    id: string,
    params: { page: number; page_size: number },
  ) => {
    const data = await request<PageResult<ApiEndpoint>>(
      `${ENDPOINT_GROUPS_PATH}/${id}/endpoints`,
      { query: { ...params } },
    )
    return { ...data, items: data.items ?? [] }
  },
  addEndpoint: (id: string, endpointId: string) =>
    request<ApiEndpointGroupMember>(`${ENDPOINT_GROUPS_PATH}/${id}/endpoints`, {
      method: 'POST',
      body: { endpoint_id: endpointId },
    }),
  removeEndpoint: (id: string, endpointId: string) =>
    request<{ status: string }>(
      `${ENDPOINT_GROUPS_PATH}/${id}/endpoints/${endpointId}`,
      { method: 'DELETE' },
    ),
}
