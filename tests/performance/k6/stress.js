import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';
import { setResponseCallback, expectedStatuses } from 'k6/http';


setResponseCallback(expectedStatuses(200, 302, 403, 429));


const wafBlockRate = new Rate('waf_block_rate');
const wafFpRate = new Rate('waf_fp_rate');
const rateLimited = new Counter('rate_limited_429');
const attackBlocked = new Counter('attack_blocked_403');
const cleanPassed = new Counter('clean_passed_200');
const attackLatency = new Trend('attack_req_latency_ms', true);
const cleanLatency = new Trend('clean_req_latency_ms', true);
const networkErrRate = new Rate('network_error_rate');

export const options = {
    stages: [
        { duration: '30s', target: 10 },
        { duration: '60s', target: 50 },
        { duration: '60s', target: 100 },
        { duration: '60s', target: 100 },
        { duration: '30s', target: 0 },
    ],
    thresholds: {
        http_req_duration: ['p(95)<1000'],
        clean_req_latency_ms: ['p(95)<600'],
        waf_block_rate: ['rate>0.85'],
        waf_fp_rate: ['rate<0.05'],
        network_error_rate: ['rate<0.02'],
    },
    insecureSkipTLSVerify: true,
};

const BASE_URL = __ENV.WAF_URL || 'https://localhost';

// ─── ATTACK PAYLOADS (GET) — URL-encoded ─────────────────────────────────────
const ATTACK_PAYLOADS_GET = [
    // SQLi Classic / Tautology
    `${BASE_URL}/search?q=%27%20OR%20%271%27%3D%271`,                   // ' OR '1'='1
    `${BASE_URL}/search?q=%27%20OR%201%3D1--`,                          // ' OR 1=1--
    `${BASE_URL}/search?q=admin%27--`,                                   // admin'--
    `${BASE_URL}/search?q=1%27%20AND%20%271%27%3D%271`,                 // 1' AND '1'='1

    // SQLi UNION / Exfil
    `${BASE_URL}/search?q=1%20UNION%20SELECT%201%2C2%2C3--`,            // 1 UNION SELECT 1,2,3--
    `${BASE_URL}/search?q=%27%20UNION%20ALL%20SELECT%20NULL%2CNULL--`,  // ' UNION ALL SELECT NULL,NULL--
    `${BASE_URL}/search?q=%27%20UNION%20SELECT%20table_name%20FROM%20information_schema.tables--`,

    // SQLi Blind / Time-based
    `${BASE_URL}/search?q=1%27%20AND%20SLEEP%285%29--`,                 // 1' AND SLEEP(5)--
    `${BASE_URL}/search?q=1%27%20AND%20BENCHMARK%281000000%2CMD5%281%29%29--`,

    // SQLi Stacked Queries
    `${BASE_URL}/search?q=%27%3B%20DROP%20TABLE%20users--`,             // '; DROP TABLE users--

    // SQLi Encoding Bypass
    `${BASE_URL}/search?q=0x27206f7220%200x313d31`,                     // hex encoded ' or 1=1
    `${BASE_URL}/search?q=%2527%20OR%20%25271%2527%253D%25271`,         // double URL-encoded
    `${BASE_URL}/search?q=%27%20UN%2F%2A%2A%2FION%20SE%2F%2A%2A%2FLECT%201%2C2--`, // comment obfusc
    `${BASE_URL}/search?q=%27%09OR%091%3D1--`,                          // tab-encoded OR

    // XSS Classic
    `${BASE_URL}/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E`,    // <script>alert(1)</script>
    `${BASE_URL}/search?q=%3CSCRIPT%3Ealert%281%29%3C%2FSCRIPT%3E`,    // uppercase

    // XSS Event Handlers
    `${BASE_URL}/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E`,  // <img onerror=...>
    `${BASE_URL}/search?q=%3Csvg%20onload%3Dalert%281%29%3E`,             // <svg onload=...>
    `${BASE_URL}/search?q=%3Cbody%20onload%3Dalert%281%29%3E`,
    `${BASE_URL}/search?q=%3Cinput%20autofocus%20onfocus%3Dalert%281%29%3E`,
    `${BASE_URL}/search?q=%3Cdetails%20open%20ontoggle%3Dalert%281%29%3E`,
    `${BASE_URL}/search?q=%3Cmarquee%20onstart%3Dalert%281%29%3E`,

    // XSS JS Protocol
    `${BASE_URL}/search?q=%3Ca%20href%3D%27javascript%3Aalert%281%29%27%3EXSS%3C%2Fa%3E`,

    // XSS Encoding Bypass — HTML Entity (NEW)
    //   &#60;script&#62;alert(1)&#60;/script&#62;
    `${BASE_URL}/search?q=%26%2360%3Bscript%26%2362%3Balert%281%29%26%2360%3B%2Fscript%26%2362%3B`,
];

// ─── ATTACK PAYLOADS (POST) ───────────────────────────────────────────────────
const ATTACK_PAYLOADS_POST = [
    { url: `${BASE_URL}/login`, body: { username: "' OR '1'='1", password: "x" } },
    { url: `${BASE_URL}/login`, body: { username: "admin'--", password: "x" } },
    { url: `${BASE_URL}/login`, body: { username: "<script>alert(1)</script>", password: "x" } },
    { url: `${BASE_URL}/login`, body: { username: "' UNION SELECT 1,2--", password: "x" } },
    { url: `${BASE_URL}/search`, body: { q: "1 UNION SELECT username,password FROM users--" } },
    { url: `${BASE_URL}/search`, body: { q: "<img src=x onerror=alert(1)>" } },
];

// ─── CLEAN PAYLOADS — ต้องผ่าน 200 ──────────────────────────────────────────
const CLEAN_PAYLOADS = [
    `${BASE_URL}/search?q=laptop`,
    `${BASE_URL}/search?q=phone`,
    `${BASE_URL}/search?q=hello%20world`,
    `${BASE_URL}/search?q=select%20your%20product`,    // benign "select"
    `${BASE_URL}/search?q=update%20me%20with%20news`,  // benign "update"
    `${BASE_URL}/search?q=order%20by%20price`,         // benign "order by"
    `${BASE_URL}/search?q=where%20is%20the%20gym`,     // benign "where"
    `${BASE_URL}/search?q=apple%20banana%20cherry`,
    `${BASE_URL}/`,
    `${BASE_URL}/login`,
];

// ─── Main Function ────────────────────────────────────────────────────────────
export default function () {
    const rand = Math.random();

    if (rand < 0.25) {
        // ── 25%: GET attack ──────────────────────────────────────────────────
        const url = ATTACK_PAYLOADS_GET[Math.floor(Math.random() * ATTACK_PAYLOADS_GET.length)];
        const res = http.get(url, { timeout: '10s' });
        networkErrRate.add(res.status === 0);
        attackLatency.add(res.timings.duration);


        if (res.status === 429) {
            rateLimited.add(1);
        } else {
            const blocked = check(res, { 'attack blocked (403)': r => r.status === 403 });
            wafBlockRate.add(blocked ? 1 : 0);
            if (blocked) attackBlocked.add(1);
        }

    } else if (rand < 0.35) {
        // ── 10%: POST attack ─────────────────────────────────────────────────
        const item = ATTACK_PAYLOADS_POST[Math.floor(Math.random() * ATTACK_PAYLOADS_POST.length)];
        const res = http.post(item.url, item.body, { timeout: '10s' });
        networkErrRate.add(res.status === 0);
        attackLatency.add(res.timings.duration);

        if (res.status === 429) {
            rateLimited.add(1);
        } else {
            const blocked = check(res, { 'attack blocked (403)': r => r.status === 403 });
            wafBlockRate.add(blocked ? 1 : 0);
            if (blocked) attackBlocked.add(1);
        }

    } else {
        // ── 65%: clean traffic ────────────────────────────────────────────────
        const url = CLEAN_PAYLOADS[Math.floor(Math.random() * CLEAN_PAYLOADS.length)];
        const res = http.get(url, { timeout: '10s' });
        networkErrRate.add(res.status === 0);
        cleanLatency.add(res.timings.duration);


        if (res.status === 429) {
            rateLimited.add(1);
        } else {
            const fp = check(res, { 'clean traffic blocked (FP ❌)': r => r.status === 403 });
            const ok = check(res, { 'clean traffic passed (200 ✅)': r => r.status === 200 });
            wafFpRate.add(fp ? 1 : 0);
            if (ok) cleanPassed.add(1);
        }
    }

    sleep(0.1);
}
