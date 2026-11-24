// WDSP v1.11.1 六合一开环压力测试套件（k6）
// 支持场景（通过 -e SCENARIO=... 选择）：
//   1. rps_step      : 开环阶梯加压（20% -> 40% -> 60% -> 80% -> 100% -> 120% -> 150% BASE_RPS）
//   2. bandwidth     : 16K/64K 大包吞吐摸底（测多 Gbps / 内网带宽极限）
//   3. tls_cps       : HTTPS 短连接新建握手速率（noConnectionReuse=true + Connection: close）
//   4. mixed_attack  : 80% 正常 GET/POST + 10% 16K/大包 + 10% 合成攻击（严格分离正常错误与预期 401/403）
//   5. event_storm   : 恒定高事件率（命中 API resource 事件），用于标定入库上限 E_max 与零丢失对账
//   6. soak          : 24h / 72h 长稳混合流量（控制正常流量 + 受控事件比例）
//
// 示例：
//   k6 run -e SCENARIO=rps_step -e TARGET_BASE_URL=https://10.10.1.10 -e TARGET_HOST=bench.wdsp.local \
//     -e RUN_PREFIX=ky-p6-r1 -e BASE_RPS=5000 -e SUMMARY_OUT=out/rps_step.json k6/wdsp-suite.js

import http from 'k6/http';
import { check } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

const SCENARIO = (__ENV.SCENARIO || 'rps_step').trim();
const TARGET_BASE_URL = (__ENV.TARGET_BASE_URL || 'http://127.0.0.1:18080').replace(/\/+$/, '');
const TARGET_HOST = (__ENV.TARGET_HOST || 'bench.wdsp.local').trim();
const RUN_PREFIX = (__ENV.RUN_PREFIX || `wdsp-${Date.now()}`).trim();
const BASE_RPS = Number(__ENV.BASE_RPS || '1000');
const DURATION = (__ENV.DURATION || '180s').trim();
const WARMUP = (__ENV.WARMUP || '60s').trim();
const STAGE_DURATION = (__ENV.STAGE_DURATION || '180s').trim();
const PRE_ALLOCATED_VUS = Number(__ENV.PRE_ALLOCATED_VUS || '200');
const MAX_VUS = Number(__ENV.MAX_VUS || '2000');
const PAYLOAD_PATH = (__ENV.PAYLOAD_PATH || '/static/64k.bin').trim();
const TARGET_PATH = (__ENV.TARGET_PATH || '').trim();
const EXPECT_BLOCK = (__ENV.EXPECT_BLOCK || '1') === '1';
const INSECURE_SKIP_TLS = (__ENV.INSECURE_SKIP_TLS_VERIFY || 'true') === 'true';
const WRITE_ENDPOINT_BUCKETS = Math.max(1, Number(__ENV.WRITE_ENDPOINT_BUCKETS || '25'));
const SOAK_ATTACK_RATIO = Number(__ENV.SOAK_ATTACK_RATIO || '0.02');
const SOAK_EVENT_RATIO = Number(__ENV.SOAK_EVENT_RATIO || '0.05');
const SUMMARY_OUT = (__ENV.SUMMARY_OUT || '').trim();

// 自定义精准指标（绝不将预期 401/403 混入正常流量错误率）
const normalTotal = new Counter('wdsp_normal_requests_total');
const normalUnexpectedErr = new Rate('wdsp_normal_unexpected_error_rate');
const normalFalsePositive = new Rate('wdsp_normal_false_positive_rate');
const normalLatency = new Trend('wdsp_normal_latency_ms', true);

const attackTotal = new Counter('wdsp_attack_requests_total');
const attackBlockedRate = new Rate('wdsp_attack_blocked_rate');
const attackLatency = new Trend('wdsp_attack_latency_ms', true);

const status2xx = new Counter('wdsp_status_2xx');
const status401_403 = new Counter('wdsp_status_401_403');
const status429 = new Counter('wdsp_status_429');
const status5xx = new Counter('wdsp_status_5xx');
const statusTransportErr = new Counter('wdsp_status_transport_err');

const postBody2K = JSON.stringify({
  order_id: 100001,
  channel: 'stress-test',
  currency: 'CNY',
  amount: 99.5,
  note: 'A'.repeat(1850),
});

const postBody16K = JSON.stringify({
  order_id: 200002,
  channel: 'stress-test-16k',
  items: [{ sku: 'SKU-001', qty: 2 }, { sku: 'SKU-002', qty: 5 }],
  payload: 'B'.repeat(16000),
});

function buildScenarios() {
  switch (SCENARIO) {
    case 'rps_step':
      return {
        rps_step: {
          executor: 'ramping-arrival-rate',
          startRate: Math.max(1, Math.round(BASE_RPS * 0.2)),
          timeUnit: '1s',
          preAllocatedVUs: PRE_ALLOCATED_VUS,
          maxVUs: MAX_VUS,
          stages: [
            { target: Math.max(1, Math.round(BASE_RPS * 0.2)), duration: WARMUP },
            { target: Math.max(1, Math.round(BASE_RPS * 0.4)), duration: STAGE_DURATION },
            { target: Math.max(1, Math.round(BASE_RPS * 0.6)), duration: STAGE_DURATION },
            { target: Math.max(1, Math.round(BASE_RPS * 0.8)), duration: STAGE_DURATION },
            { target: Math.max(1, Math.round(BASE_RPS * 1.0)), duration: STAGE_DURATION },
            { target: Math.max(1, Math.round(BASE_RPS * 1.2)), duration: STAGE_DURATION },
            { target: Math.max(1, Math.round(BASE_RPS * 1.5)), duration: STAGE_DURATION },
          ],
        },
      };
    case 'bandwidth':
      return {
        bandwidth: {
          executor: 'constant-arrival-rate',
          rate: BASE_RPS,
          timeUnit: '1s',
          duration: DURATION,
          preAllocatedVUs: PRE_ALLOCATED_VUS,
          maxVUs: MAX_VUS,
        },
      };
    case 'tls_cps':
      return {
        tls_cps: {
          executor: 'constant-arrival-rate',
          rate: BASE_RPS,
          timeUnit: '1s',
          duration: DURATION,
          preAllocatedVUs: PRE_ALLOCATED_VUS,
          maxVUs: MAX_VUS,
        },
      };
    case 'mixed_attack':
      return {
        mixed_attack: {
          executor: 'constant-arrival-rate',
          rate: BASE_RPS,
          timeUnit: '1s',
          duration: DURATION,
          preAllocatedVUs: PRE_ALLOCATED_VUS,
          maxVUs: MAX_VUS,
        },
      };
    case 'event_storm':
      return {
        event_storm: {
          executor: 'constant-arrival-rate',
          rate: BASE_RPS,
          timeUnit: '1s',
          duration: DURATION,
          preAllocatedVUs: PRE_ALLOCATED_VUS,
          maxVUs: MAX_VUS,
        },
      };
    case 'soak':
      return {
        soak: {
          executor: 'constant-arrival-rate',
          rate: BASE_RPS,
          timeUnit: '1s',
          duration: DURATION,
          preAllocatedVUs: PRE_ALLOCATED_VUS,
          maxVUs: MAX_VUS,
        },
      };
    default:
      throw new Error(`Unsupported SCENARIO=${SCENARIO}`);
  }
}

export const options = {
  insecureSkipTLSVerify: INSECURE_SKIP_TLS,
  noConnectionReuse: SCENARIO === 'tls_cps',
  discardResponseBodies: true,
  scenarios: buildScenarios(),
  summaryTrendStats: ['min', 'avg', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  thresholds: {
    wdsp_normal_unexpected_error_rate: ['rate<=0.001'],
    wdsp_normal_false_positive_rate: ['rate==0'],
  },
};

const normalExpected = http.expectedStatuses(200);
const attackExpected = EXPECT_BLOCK
  ? http.expectedStatuses(401, 403)
  : http.expectedStatuses(200, 401, 403);

function baseHeaders(extra) {
  const headers = { Host: TARGET_HOST };
  if (SCENARIO === 'tls_cps') {
    headers.Connection = 'close';
  }
  if (extra) {
    Object.assign(headers, extra);
  }
  return headers;
}

function recordStatusCode(status) {
  if (status === 0) {
    statusTransportErr.add(1);
  } else if (status >= 200 && status < 300) {
    status2xx.add(1);
  } else if (status === 401 || status === 403) {
    status401_403.add(1);
  } else if (status === 429) {
    status429.add(1);
  } else if (status >= 500) {
    status5xx.add(1);
  }
}

function recordNormal(res) {
  recordStatusCode(res.status);
  normalTotal.add(1);
  normalLatency.add(res.timings.duration);
  const isOk = res.status === 200;
  const isFalsePositive = res.status === 401 || res.status === 403;
  normalUnexpectedErr.add(!isOk);
  normalFalsePositive.add(isFalsePositive);
  check(res, { 'normal status is 200': (r) => r.status === 200 });
}

function recordAttack(res) {
  recordStatusCode(res.status);
  attackTotal.add(1);
  attackLatency.add(res.timings.duration);
  const blocked = res.status === 401 || res.status === 403;
  attackBlockedRate.add(blocked);
  if (EXPECT_BLOCK) {
    check(res, { 'attack blocked (401/403)': (r) => r.status === 401 || r.status === 403 });
  }
}

function sendSyntheticAttack(seq) {
  const kind = seq % 3;
  if (kind === 0) {
    // SQLi 合成样本（命中 Coraza CRS SQLi）
    const url = `${TARGET_BASE_URL}/v1/${RUN_PREFIX}-atk-sqli/1?id=1%27%20UNION%20SELECT%201,2,3--`;
    const res = http.get(url, {
      headers: baseHeaders(),
      tags: { bucket: 'attack_sqli' },
      responseCallback: attackExpected,
    });
    recordAttack(res);
  } else if (kind === 1) {
    // XSS 合成样本（命中 Coraza CRS XSS）
    const url = `${TARGET_BASE_URL}/v1/${RUN_PREFIX}-atk-xss/1?q=%3Cscript%3Ealert(1)%3C/script%3E`;
    const res = http.get(url, {
      headers: baseHeaders(),
      tags: { bucket: 'attack_xss' },
      responseCallback: attackExpected,
    });
    recordAttack(res);
  } else {
    // 敏感字段出现在 query（命中 WDSP API sensitive.in_query BLOCK）
    const url = `${TARGET_BASE_URL}/v1/${RUN_PREFIX}-atk-sens/1?password=wdsp_synthetic_probe`;
    const res = http.get(url, {
      headers: baseHeaders(),
      tags: { bucket: 'attack_sensitive_query' },
      responseCallback: attackExpected,
    });
    recordAttack(res);
  }
}

export default function () {
  const seq = (__VU * 1000000 + __ITER) >>> 0;

  if (SCENARIO === 'rps_step') {
    const path = TARGET_PATH || `/v1/${RUN_PREFIX}-rps/1`;
    const res = http.get(`${TARGET_BASE_URL}${path}`, {
      headers: baseHeaders(),
      tags: { bucket: 'rps_step' },
      responseCallback: normalExpected,
    });
    recordNormal(res);
    return;
  }

  if (SCENARIO === 'bandwidth') {
    const res = http.get(`${TARGET_BASE_URL}${PAYLOAD_PATH}`, {
      headers: baseHeaders(),
      tags: { bucket: 'bandwidth' },
      responseCallback: normalExpected,
    });
    recordNormal(res);
    return;
  }

  if (SCENARIO === 'tls_cps') {
    const path = TARGET_PATH || '/static/256b.txt';
    const res = http.get(`${TARGET_BASE_URL}${path}`, {
      headers: baseHeaders(),
      tags: { bucket: 'tls_cps' },
      responseCallback: normalExpected,
    });
    recordNormal(res);
    return;
  }

  if (SCENARIO === 'event_storm') {
    // 无凭据 + 数字对象段，确保每请求稳定命中 API resource 运行时事件，便于对账
    const objId = (seq % 1000) + 1;
    const res = http.get(`${TARGET_BASE_URL}/v1/${RUN_PREFIX}-evt/${objId}`, {
      headers: baseHeaders(),
      tags: { bucket: 'event_storm' },
      responseCallback: normalExpected,
    });
    recordNormal(res);
    return;
  }

  if (SCENARIO === 'mixed_attack') {
    const r = Math.random();
    if (r < 0.60) {
      const res = http.get(`${TARGET_BASE_URL}/v1/${RUN_PREFIX}-get/1`, {
        headers: baseHeaders(),
        tags: { bucket: 'normal_get' },
        responseCallback: normalExpected,
      });
      recordNormal(res);
    } else if (r < 0.80) {
      const b = seq % WRITE_ENDPOINT_BUCKETS;
      const res = http.post(`${TARGET_BASE_URL}/v1/${RUN_PREFIX}-post-${b}/1`, postBody2K, {
        headers: baseHeaders({ 'Content-Type': 'application/json' }),
        tags: { bucket: 'normal_post_2k' },
        responseCallback: normalExpected,
      });
      recordNormal(res);
    } else if (r < 0.90) {
      const b = seq % WRITE_ENDPOINT_BUCKETS;
      const res = http.post(`${TARGET_BASE_URL}/v1/${RUN_PREFIX}-big-${b}/1`, postBody16K, {
        headers: baseHeaders({ 'Content-Type': 'application/json' }),
        tags: { bucket: 'normal_post_16k' },
        responseCallback: normalExpected,
      });
      recordNormal(res);
    } else {
      sendSyntheticAttack(seq);
    }
    return;
  }

  if (SCENARIO === 'soak') {
    const r = Math.random();
    if (r < SOAK_ATTACK_RATIO) {
      sendSyntheticAttack(seq);
    } else if (r < SOAK_ATTACK_RATIO + SOAK_EVENT_RATIO) {
      // 受控比例走 API 事件端点，确保长稳期间事件采集链持续运转但不无限积压
      const res = http.get(`${TARGET_BASE_URL}/v1/${RUN_PREFIX}-soak-evt/1`, {
        headers: baseHeaders(),
        tags: { bucket: 'soak_api_event' },
        responseCallback: normalExpected,
      });
      recordNormal(res);
    } else {
      // 主体正常静态/常规 Web 流量
      const res = http.get(`${TARGET_BASE_URL}/static/4k.bin`, {
        headers: baseHeaders(),
        tags: { bucket: 'soak_normal_web' },
        responseCallback: normalExpected,
      });
      recordNormal(res);
    }
  }
}

export function handleSummary(data) {
  const out = {};
  if (SUMMARY_OUT) {
    out[SUMMARY_OUT] = JSON.stringify(
      {
        meta: {
          scenario: SCENARIO,
          target_base_url: TARGET_BASE_URL,
          target_host: TARGET_HOST,
          run_prefix: RUN_PREFIX,
          base_rps: BASE_RPS,
          duration: DURATION,
          expect_block: EXPECT_BLOCK,
          generated_at_utc: new Date().toISOString(),
        },
        metrics: data.metrics,
      },
      null,
      2
    );
  }
  return out;
}
