/*
 * k6 load test. Produces the throughput and latency numbers quoted in the README.
 *
 *   docker run --rm -i -e BASE_URL=https://your-service.run.app grafana/k6 run - <scripts/load-test.js
 *
 * Token verification is the hot path in an auth service: it happens on every request
 * to every protected endpoint, so that is what this measures. Login is deliberately
 * rare here — Argon2 is meant to be slow, and hammering it would measure the hash,
 * not the service.
 */
import http from 'k6/http';
import { check, group } from 'k6';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8000';

export const options = {
  scenarios: {
    ramp: {
      executor: 'ramping-vus',
      startVUs: 1,
      stages: [
        { duration: '30s', target: 20 },
        { duration: '1m', target: 50 },
        { duration: '30s', target: 0 },
      ],
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.01'],
    'http_req_duration{endpoint:verify}': ['p(95)<300'],
  },
};

export function setup() {
  const email = `loadtest-${Date.now()}@example.com`;
  const password = 'l0ad-test-passw0rd';

  http.post(`${BASE_URL}/auth/register`, JSON.stringify({ email, password }), {
    headers: { 'Content-Type': 'application/json' },
  });
  const login = http.post(`${BASE_URL}/auth/login`, { username: email, password });
  check(login, { 'logged in': (r) => r.status === 200 });

  return { accessToken: login.json('access_token') };
}

export default function (data) {
  const authed = {
    headers: { Authorization: `Bearer ${data.accessToken}` },
    tags: { endpoint: 'verify' },
  };

  group('verify a token on a protected endpoint', () => {
    const res = http.get(`${BASE_URL}/auth/me`, authed);
    check(res, { 'me: 200': (r) => r.status === 200 });
  });

  group('health', () => {
    const res = http.get(`${BASE_URL}/health`, { tags: { endpoint: 'health' } });
    check(res, { 'health: 200': (r) => r.status === 200 });
  });
}
