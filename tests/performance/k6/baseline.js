import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';
import { setResponseCallback, expectedStatuses } from 'k6/http';


setResponseCallback(expectedStatuses(200, 302, 403, 429));

const errorRate = new Rate('error_rate');
const wafLatency = new Trend('waf_latency_ms', true);
const status200 = new Counter('resp_status_200');
const status403 = new Counter('resp_status_403');
const status429 = new Counter('resp_status_429');
const status5xx = new Counter('resp_status_5xx');
const statusOther = new Counter('resp_status_other');

export const options = {
    stages: [
        { duration: '10s', target: 5 },
        { duration: '30s', target: 10 },
        { duration: '10s', target: 0 },
    ],
    thresholds: {
        http_req_duration: ['p(95)<500'],
        error_rate: ['rate<0.05'],
        resp_status_403: ['count<5'],
    },
    insecureSkipTLSVerify: true,
};

const BASE_URL = __ENV.WAF_URL || 'https://localhost';

const CLEAN_REQUESTS = [
    { name: 'home', url: `${BASE_URL}/`, method: 'GET' },
    { name: 'search_text', url: `${BASE_URL}/search?q=hello`, method: 'GET' },
    { name: 'search_num', url: `${BASE_URL}/search?q=product123`, method: 'GET' },
    { name: 'login_page', url: `${BASE_URL}/login`, method: 'GET' },
    { name: 'search_th', url: `${BASE_URL}/search?q=สินค้า`, method: 'GET' },
    { name: 'search_order', url: `${BASE_URL}/search?q=order+by+price`, method: 'GET' },
];

export default function () {
    const scenario = CLEAN_REQUESTS[Math.floor(Math.random() * CLEAN_REQUESTS.length)];
    const res = http.request(scenario.method, scenario.url, null, { timeout: '10s' });

    const statusOk = check(res, {
        [`${scenario.name} status 200`]: (r) => r.status === 200,
        'response time < 1s': (r) => r.timings.duration < 1000,
    });

    wafLatency.add(res.timings.duration);
    errorRate.add(res.status !== 200 && res.status !== 429);

    if (res.status === 200) status200.add(1);
    else if (res.status === 403) status403.add(1);
    else if (res.status === 429) status429.add(1);
    else if (res.status >= 500 && res.status < 600) status5xx.add(1);
    else statusOther.add(1);

    sleep(0.1);
}
