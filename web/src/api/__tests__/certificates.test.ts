import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { certificatesApi } from '../certificates'
import { setCsrfToken } from '../client'

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('certificatesApi.uploadFiles', () => {
  beforeEach(() => {
    setCsrfToken('csrf-cert-token')
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    setCsrfToken(null)
  })

  it('通用协议证书：以 multipart/form-data 上传证书、私钥及可选证书链文件并携带 CSRF Token', async () => {
    const fetchMock = vi.fn(() =>
      Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { id: 'cert-1', name: 'example.com' },
        }),
      ),
    )
    vi.stubGlobal('fetch', fetchMock)

    const certFile = new File(['-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----'], 'example.com.pem')
    const keyFile = new File(['-----BEGIN PRIVATE KEY-----\nB\n-----END PRIVATE KEY-----'], 'example.com.key')
    const chainFile = new File(['-----BEGIN CERTIFICATE-----\nC\n-----END CERTIFICATE-----'], 'chain.pem')

    const res = await certificatesApi.uploadFiles({
      name: 'example.com',
      protocol_type: 'INTERNATIONAL',
      cert_file: certFile,
      key_file: keyFile,
      chain_file: chainFile,
    })

    expect(res.id).toBe('cert-1')
    expect(fetchMock).toHaveBeenCalledTimes(1)
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit]
    expect(url).toBe('/api/v1/certificates')
    expect(init.method).toBe('POST')
    expect(init.credentials).toBe('include')
    expect((init.headers as Record<string, string>)['X-CSRF-Token']).toBe('csrf-cert-token')
    expect((init.headers as Record<string, string>)['Content-Type']).toBeUndefined()
    expect(init.body).toBeInstanceOf(FormData)

    const form = init.body as FormData
    expect(form.get('name')).toBe('example.com')
    expect(form.get('protocol_type')).toBe('INTERNATIONAL')
    expect(form.get('cert_file')).toBe(certFile)
    expect(form.get('key_file')).toBe(keyFile)
    expect(form.get('chain_file')).toBe(chainFile)
    expect(form.get('enc_cert_file')).toBeNull()
    expect(form.get('enc_key_file')).toBeNull()
  })

  it('国密 SM_TLCP 双证书：附带签名与加密全部四个文件字段', async () => {
    const fetchMock = vi.fn(() =>
      Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { id: 'cert-gm-1', name: 'gm.example.com' },
        }),
      ),
    )
    vi.stubGlobal('fetch', fetchMock)

    const signCert = new File(['sign-cert'], 'sign.crt')
    const signKey = new File(['sign-key'], 'sign.key')
    const encCert = new File(['enc-cert'], 'enc.crt')
    const encKey = new File(['enc-key'], 'enc.key')

    await certificatesApi.uploadFiles({
      name: 'gm.example.com',
      protocol_type: 'SM_TLCP',
      cert_file: signCert,
      key_file: signKey,
      enc_cert_file: encCert,
      enc_key_file: encKey,
      chain_file: null,
    })

    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit]
    const form = init.body as FormData
    expect(form.get('protocol_type')).toBe('SM_TLCP')
    expect(form.get('cert_file')).toBe(signCert)
    expect(form.get('key_file')).toBe(signKey)
    expect(form.get('enc_cert_file')).toBe(encCert)
    expect(form.get('enc_key_file')).toBe(encKey)
    expect(form.get('chain_file')).toBeNull()
  })
})
