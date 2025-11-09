import React, { useMemo, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  ShieldAlert,
  ShieldCheck,
  Upload,
  Search as SearchIcon,
  Bug,
  Globe,
  Loader2,
  ExternalLink,
  Download,
  XCircle,
  Copy,
  Check,
  ChevronDown,
  ChevronRight,
} from "lucide-react";

/**
 * Hacklipse — Frontend-only demo shell for a web vuln scanning UI (JavaScript version).
 *
 * ✅ What this file gives you now
 *  - Clean, production-style UI with Tailwind
 *  - Centered URL form; on submit it hides, shows a scanning state, then a concise report view
 *  - Report view with summary counts and expandable findings
 *  - Optional manual import of JSON (nuclei/wapiti) with client-side normalization
 *  - Export findings as JSON/CSV
 *
 * 🔌 How to hook your backend later
 *  1) Implement GET /api/scan?url=... returning a normalized payload:
 *     {
 *       target: string,
 *       startedAt: ISODateString,
 *       finishedAt: ISODateString,
 *       tools: string[],
 *       findings: NormalizedFinding[]
 *     }
 *  2) Replace `fetchScanResults` with a real fetch.
 */

const API_BASE_URL = 'http://localhost:3000';
const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const SEVERITY_COLORS = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-amber-400 text-black",
  low: "bg-emerald-400 text-black",
  info: "bg-slate-300 text-black",
};

function isValidUrl(u) {
  try {
    const url = new URL(u);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch (e) {
    return false;
  }
}

function classNames() {
  return Array.from(arguments).filter(Boolean).join(" ");
}

// ------------------------- Demo / Fallback Data ------------------------- //

const demoPayload = {
  target: "https://demo.example",
  startedAt: new Date(Date.now() - 1000 * 25).toISOString(),
  finishedAt: new Date().toISOString(),
  tools: ["ffuf", "wapiti", "nuclei"],
  findings: [
    {
      id: "nuclei-1",
      tool: "nuclei",
      severity: "high",
      title: "Exposed admin panel discovered",
      description:
        "An admin login interface was identified. If default credentials or weak auth are present, takeover is possible.",
      endpoint: "https://demo.example/admin/",
      method: "GET",
      cwe: "CWE-284",
      cvss: 8.1,
      evidence: "Matched nuclei template admin-panel-detect@http",
      recommendation:
        "Restrict access (IP allowlist/VPN), enforce MFA, disable default creds, and move panel behind auth proxy.",
      references: [
        "https://owasp.org/www-project-top-ten/",
        "https://cwe.mitre.org/data/definitions/284.html",
      ],
    },
    {
      id: "wapiti-1",
      tool: "wapiti",
      severity: "medium",
      title: "Reflected XSS via query parameter",
      description:
        "Unescaped query parameter echoed in response. May lead to session hijacking or defacement.",
      endpoint: "https://demo.example/search?q=term",
      method: "GET",
      cwe: "CWE-79",
      cvss: 6.1,
      evidence: "Payload <svg onload=alert(1)> reflected in HTML",
      recommendation:
        "Apply output encoding, use templating auto-escape, and implement CSP 'script-src' nonce-based policy.",
      references: [
        "https://owasp.org/www-community/attacks/xss/",
        "https://cwe.mitre.org/data/definitions/79.html",
      ],
    },
    {
      id: "nuclei-2",
      tool: "nuclei",
      severity: "low",
      title: "Server version disclosure in headers",
      description:
        "The 'Server' header reveals software version which can aid targeted exploits.",
      endpoint: "https://demo.example/",
      method: "GET",
      cwe: "CWE-200",
      cvss: 3.1,
      evidence: "Server: nginx/1.18.0",
      recommendation:
        "Hide or generalize server banner via reverse proxy; keep software patched.",
      references: [
        "https://cwe.mitre.org/data/definitions/200.html",
      ],
    },
  ],
};

async function fetchScanResults(url, extras = {}) {
  const { cookie, headers } = extras || {};
  try {
    // cookie/headers가 있으면 POST 시도
    if ((cookie && cookie.trim()) || (headers && headers.trim())) {
      try {
        const res = await fetch(`${API_BASE_URL}/api/scan`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url, cookies: cookie, headers }),
        });
        if (!res.ok) throw new Error("non-200");
        const data = await res.json();
        if (!data.findings && (Array.isArray(data) || data.nuclei || data.wapiti)) {
          return normalizeMixedPayload(data, url);
        }
        return data;
      } catch (_) {
        // 실패 시 GET로 폴백
      }
    }

    // 기본 GET (기존 동작)
    const res = await fetch(`${API_BASE_URL}/api/scan?url=${encodeURIComponent(url)}`);
    if (!res.ok) throw new Error("non-200");
    const data = await res.json();
    if (!data.findings && (Array.isArray(data) || data.nuclei || data.wapiti)) {
      return normalizeMixedPayload(data, url);
    }
    return data;
  } catch (e) {
    await new Promise((r) => setTimeout(r, 900));
    return { ...demoPayload, target: url };
  }
}

// ------------------------- Client-side Normalization ------------------------- //

function normalizeEndpoint(url) {
  if (!url) return url;
  // Remove query parameters
  if (url.includes('?')) {
    url = url.split('?')[0];
  }
  // Remove fragment
  if (url.includes('#')) {
    url = url.split('#')[0];
  }
  return url;
}

function normalizeMixedPayload(raw, target) {
  const findings = [];

  function push(f) {
    if (!f || !f.title) return;
    const sev = (f.severity || "info").toLowerCase();
    const fullUrl = f.endpoint;
    const endpoint = normalizeEndpoint(f.endpoint);

    findings.push({
      id: f.id || `${f.tool || "unknown"}-${findings.length + 1}-${Date.now()}`,
      tool: f.tool || "unknown",
      severity: SEVERITY_ORDER.includes(sev) ? sev : "info",
      title: f.title,
      description: f.description,
      endpoint: endpoint,
      fullUrl: fullUrl !== endpoint ? fullUrl : undefined,
      method: f.method,
      cwe: f.cwe,
      cvss: f.cvss,
      evidence: f.evidence,
      recommendation: f.recommendation,
      references: Array.isArray(f.references)
        ? f.references
        : f.references
        ? [String(f.references)]
        : [],
    });
  }

  // Nuclei JSON Lines or array
  if (Array.isArray(raw)) {
    raw.forEach((item) => {
      const info = item.info || {};
      push({
        tool: "nuclei",
        severity: info.severity || item.severity,
        title: info.name || item.templateID || "Nuclei finding",
        description: info.description,
        endpoint: item["matched-at"] || item.host,
        method: item.method,
        cwe:
          (info.tags || "")
            .split(",")
            .find((t) => t.trim().toLowerCase().startsWith("cwe-")) || undefined,
        cvss: info.cvssScore || undefined,
        evidence:
          item["matcher-name"] || (item["extracted-results"] || []).join(", "),
        references: Array.isArray(info.reference)
          ? info.reference
          : info.reference
          ? [info.reference]
          : [],
      });
    });
  }

  // Wapiti object
  if (raw && raw.vulnerabilities) {
    (raw.vulnerabilities || []).forEach((v) => {
      const level = (v.level || v.severity || "info").toLowerCase();
      push({
        tool: "wapiti",
        severity: level,
        title: v.title || v.module || v.vulnerability || "Wapiti finding",
        description: v.message || v.description,
        endpoint: v.path,
        method: v.http_method || v.method,
        cwe: v.cwe,
        cvss: v.cvss,
        evidence: v.proof || v.info,
        recommendation: v.solution || v.remediation,
        references: v.references || [],
      });
    });
  }

  // Already normalized
  if (raw && raw.findings && Array.isArray(raw.findings)) {
    raw.findings.forEach(push);
  }

  return {
    target: target || raw.target || "",
    startedAt: raw.startedAt || new Date().toISOString(),
    finishedAt: raw.finishedAt || new Date().toISOString(),
    tools: raw.tools || Array.from(new Set(findings.map((f) => f.tool).filter(Boolean))),
    findings,
  };
}

// ------------------------------ Utilities ------------------------------ //

function downloadFile(filename, text) {
  const blob = new Blob([text], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function toCSV(findings) {
  function esc(s) {
    return '"' + String(s == null ? "" : s).replaceAll('"', '""') + '"';
  }
  const headers = [
    "tool",
    "severity",
    "title",
    "endpoint",
    "method",
    "cwe",
    "cvss",
    "evidence",
  ];
  const rows = findings.map((f) =>
    [
      f.tool,
      f.severity,
      f.title,
      f.endpoint,
      f.method,
      f.cwe,
      f.cvss,
      f.evidence,
    ].map(esc).join(",")
  );
  return [headers.join(","), ...rows].join("\n");
}

// ------------------------------ UI Parts ------------------------------ //

// in front/app.jsx — Header 컴포넌트 내 왼쪽 로고 영역 교체
function Header({ onHomeClick }) {
  return (
    <header className="w-full border-b border-slate-200/60 bg-white/70 backdrop-blur sticky top-0 z-20">
      <div className="mx-auto max-w-6xl px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          {/* 로고 이미지 */}
          <button
            onClick={onHomeClick}
            className="cursor-pointer hover:opacity-80 transition-opacity"
          >
            <img
              src="/logo.png"
              alt="Hacklipse"
              className="h-7 w-auto"
              draggable={false}
            />
          </button>
        </div>
        <a
          href="https://owasp.org/"
          target="_blank"
          rel="noreferrer"
          className="inline-flex items-center gap-2 text-sm text-slate-600 hover:text-slate-900"
        >
        <ExternalLink className="h-4 w-4" />
          OWASP
        </a>
      </div>
    </header>
  );
}

function UrlForm({ onSubmit }) {
  const [url, setUrl] = useState("");
  const [touched, setTouched] = useState(false);
  const [cookie, setCookie] = useState("");
  const [headers, setHeaders] = useState("");
  const valid = isValidUrl(url);

  function handleSubmit(e) {
    e.preventDefault();
    setTouched(true);
    if (!valid) return;
    onSubmit(url, { cookie, headers });
  }

  return (
    <div className="min-h-[60vh] grid place-items-center">
      <motion.form
        onSubmit={handleSubmit}
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-2xl rounded-2xl border border-slate-200 shadow-sm bg-white p-6"
      >
        <div className="flex items-center gap-3 mb-4">
          <Globe className="h-5 w-5 text-slate-600" />
          <h2 className="text-lg font-semibold">대상 URL 입력</h2>
        </div>
        <div className="flex gap-3">
          <input
            className={classNames(
              "flex-1 rounded-xl border px-4 py-3 outline-none",
              valid ? "border-slate-300 focus:ring-2 ring-slate-300" : "border-rose-300 focus:ring-2 ring-rose-300"
            )}
            placeholder="https://example.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onBlur={() => setTouched(true)}
            spellCheck={false}
          />
          <button
            type="submit"
            className="inline-flex items-center gap-2 rounded-xl bg-slate-900 text-white px-4 py-3 hover:bg-slate-800"
          >
            <SearchIcon className="h-4 w-4" />
            제출
          </button>
        </div>

        {touched && !valid && (
          <p className="mt-3 text-sm text-rose-600">올바른 http(s) URL을 입력하세요.</p>
        )}

        {/* 추가 입력란 */}
        <div className="mt-4 grid gap-3">
          <div>
            <label className="text-sm font-medium text-slate-700">(선택) Cookies </label>
            <input
              className="mt-1 w-full rounded-xl border px-3 py-2 outline-none border-slate-300 focus:ring-2 ring-slate-300"
              placeholder="session=abc; uid=1"
              value={cookie}
              onChange={(e) => setCookie(e.target.value)}
              spellCheck={false}
            />
            <p className="mt-1 text-xs text-slate-500">
            </p>
          </div>

          <div>
            <label className="text-sm font-medium text-slate-700">(선택) Headers </label>
            <textarea
              className="mt-1 w-full h-20 rounded-xl border px-3 py-2 outline-none border-slate-300 focus:ring-2 ring-slate-300 font-mono text-xs"
              placeholder="User-Agent: curl/7.0; Accept: */*"
              value={headers}
              onChange={(e) => setHeaders(e.target.value)}
              spellCheck={false}
            />
          </div>
        </div>
      </motion.form>
    </div>
  );
}


function Stat({ icon: Icon, label, value, tone }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4 flex items-center gap-4">
      <div className={classNames("rounded-lg p-2", tone || "bg-slate-100")}>
        <Icon className="h-5 w-5" />
      </div>
      <div>
        <div className="text-xs uppercase tracking-wide text-slate-500">{label}</div>
        <div className="text-xl font-semibold">{value}</div>
      </div>
    </div>
  );
}

function SeverityBadge({ severity }) {
  return (
    <span className={classNames("inline-flex items-center rounded-md px-2 py-1 text-xs font-semibold", SEVERITY_COLORS[severity] || SEVERITY_COLORS.info)}>
      {severity.toUpperCase()}
    </span>
  );
}

function FindingCard({ f, showEndpointGroup = false }) {
  const [open, setOpen] = useState(false);
  const [showRequest, setShowRequest] = useState(false);
  const [showResponse, setShowResponse] = useState(false);
  const [copied, setCopied] = useState(false);

  function copyCurlCommand() {
    if (!f.curlCommand) return;
    navigator.clipboard.writeText(f.curlCommand);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="rounded-xl border border-slate-200 bg-white">
      <button
        onClick={() => setOpen(!open)}
        className="w-full text-left p-4 flex items-center justify-between hover:bg-slate-50"
      >
        <div className="flex items-center gap-3 flex-1">
          {f.severity === "high" || f.severity === "critical" ? (
            <ShieldAlert className="h-5 w-5 text-red-600 flex-shrink-0" />
          ) : (
            <ShieldCheck className="h-5 w-5 text-emerald-600 flex-shrink-0" />
          )}
          <div className="flex-1 min-w-0">
            <div className="font-medium truncate">{f.title}</div>
            <div className="text-xs text-slate-500 flex items-center gap-2 flex-wrap">
              <span className="px-2 py-0.5 bg-slate-100 rounded">{f.tool.toUpperCase()}</span>
              {f.category && <span>· {f.category}</span>}
              {f.method && <span>· {f.method}</span>}
              {showEndpointGroup && <span className="truncate">· {f.endpoint}</span>}
            </div>
          </div>
        </div>
        <SeverityBadge severity={f.severity} />
      </button>

      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="border-t border-slate-100"
          >
            <div className="p-4 space-y-4">
              {/* Endpoint */}
              {f.endpoint && (
                <div className="bg-slate-50 rounded-lg p-3">
                  <div className="text-xs font-medium text-slate-600 mb-1">Endpoint</div>
                  <div className="text-sm font-mono break-all">{f.endpoint}</div>
                </div>
              )}

              {/* Full URL (if different from endpoint) */}
              {f.fullUrl && f.fullUrl !== f.endpoint && (
                <div className="bg-amber-50 rounded-lg p-3 border border-amber-200">
                  <div className="text-xs font-medium text-amber-700 mb-1">Full URL (with payload)</div>
                  <div className="text-sm font-mono break-all text-amber-900">{f.fullUrl}</div>
                </div>
              )}

              {/* Description */}
              {f.description && (
                <div>
                  <div className="text-xs font-medium text-slate-600 mb-1">Description</div>
                  <p className="text-sm text-slate-700">{f.description}</p>
                </div>
              )}

              {/* Impact (Nuclei) */}
              {f.impact && f.impact !== 'N/A' && (
                <div>
                  <div className="text-xs font-medium text-slate-600 mb-1">Impact</div>
                  <p className="text-sm text-slate-700">{f.impact}</p>
                </div>
              )}

              {/* Metadata Grid */}
              <div className="grid grid-cols-2 gap-3">
                {f.parameter && (
                  <div>
                    <div className="text-xs font-medium text-slate-600 mb-1">Parameter</div>
                    <code className="text-sm bg-amber-50 px-2 py-1 rounded">{f.parameter}</code>
                  </div>
                )}
                {f.cve && (
                  <div>
                    <div className="text-xs font-medium text-slate-600 mb-1">CVE ID</div>
                    <a
                      href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${f.cve}`}
                      target="_blank"
                      rel="noreferrer"
                      className="text-sm text-blue-600 hover:underline"
                    >
                      {f.cve}
                    </a>
                  </div>
                )}
                {f.ip && (
                  <div>
                    <div className="text-xs font-medium text-slate-600 mb-1">IP Address</div>
                    <code className="text-sm">{f.ip}</code>
                  </div>
                )}
                {f.cwe && (
                  <div>
                    <div className="text-xs font-medium text-slate-600 mb-1">CWE</div>
                    <span className="text-sm">{String(f.cwe)}</span>
                  </div>
                )}
                {f.cvss != null && (
                  <div>
                    <div className="text-xs font-medium text-slate-600 mb-1">CVSS</div>
                    <span className="text-sm">{String(f.cvss)}</span>
                  </div>
                )}
              </div>

              {/* Evidence */}
              {f.evidence && (
                <div>
                  <div className="text-xs font-medium text-slate-600 mb-1">Evidence</div>
                  <p className="text-sm text-slate-700">{f.evidence}</p>
                </div>
              )}

              {/* Recommendation */}
              {f.recommendation && (
                <div>
                  <div className="text-xs font-medium text-slate-600 mb-1">Recommendation</div>
                  <p className="text-sm text-slate-700">{f.recommendation}</p>
                </div>
              )}

              {/* WSTG Tags (Wapiti) */}
              {f.wstg && f.wstg.length > 0 && (
                <div>
                  <div className="text-xs font-medium text-slate-600 mb-2">OWASP WSTG</div>
                  <div className="flex flex-wrap gap-2">
                    {f.wstg.map((tag, i) => (
                      <a
                        key={i}
                        href={`https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/`}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1 px-2 py-1 bg-blue-50 text-blue-700 rounded text-xs hover:bg-blue-100"
                      >
                        {tag}
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {/* Curl Command with Copy Button */}
              {f.curlCommand && (
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <div className="text-xs font-medium text-slate-600">Curl Command</div>
                    <button
                      onClick={copyCurlCommand}
                      className="inline-flex items-center gap-1 px-2 py-1 bg-slate-100 hover:bg-slate-200 rounded text-xs"
                    >
                      {copied ? (
                        <>
                          <Check className="h-3 w-3" /> Copied!
                        </>
                      ) : (
                        <>
                          <Copy className="h-3 w-3" /> Copy
                        </>
                      )}
                    </button>
                  </div>
                  <pre className="bg-slate-900 text-slate-100 p-3 rounded-lg text-xs overflow-x-auto">
                    {f.curlCommand}
                  </pre>
                </div>
              )}

              {/* Request/Response Viewers */}
              {f.request && (
                <div>
                  <button
                    onClick={() => setShowRequest(!showRequest)}
                    className="flex items-center gap-2 text-sm font-medium text-slate-700 hover:text-slate-900"
                  >
                    {showRequest ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                    HTTP Request
                  </button>
                  {showRequest && (
                    <pre className="mt-2 bg-slate-900 text-slate-100 p-3 rounded-lg text-xs overflow-x-auto max-h-60">
                      {f.request}
                    </pre>
                  )}
                </div>
              )}

              {f.response && (
                <div>
                  <button
                    onClick={() => setShowResponse(!showResponse)}
                    className="flex items-center gap-2 text-sm font-medium text-slate-700 hover:text-slate-900"
                  >
                    {showResponse ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                    HTTP Response
                  </button>
                  {showResponse && (
                    <pre className="mt-2 bg-slate-900 text-slate-100 p-3 rounded-lg text-xs overflow-x-auto max-h-60">
                      {f.response}
                    </pre>
                  )}
                </div>
              )}

              {/* References */}
              {Array.isArray(f.references) && f.references.length > 0 && (
                <div>
                  <div className="text-xs font-medium text-slate-600 mb-2">References</div>
                  <ul className="list-disc pl-5 text-sm space-y-1">
                    {f.references.map((r, i) => (
                      <li key={i}>
                        <a
                          className="text-blue-600 hover:underline break-all"
                          href={r}
                          target="_blank"
                          rel="noreferrer"
                        >
                          {r}
                        </a>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

function ResultsListView({ onSelectResult, onBack }) {
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  React.useEffect(() => {
    async function loadResults() {
      try {
        const res = await fetch(`${API_BASE_URL}/api/results`);
        if (!res.ok) throw new Error('Failed to load results');
        const data = await res.json();
        setResults(data.results || []);
      } catch (e) {
        setError(e.message);
      } finally {
        setLoading(false);
      }
    }
    loadResults();
  }, []);

  async function handleSelectResult(filename) {
    try {
      const res = await fetch(`${API_BASE_URL}/api/results/${filename}`);
      if (!res.ok) throw new Error('Failed to load result file');
      const data = await res.json();
      onSelectResult(data);
    } catch (e) {
      setError(e.message);
    }
  }

  if (loading) {
    return (
      <div className="min-h-[60vh] grid place-items-center">
        <div className="flex flex-col items-center gap-3 text-slate-700">
          <Loader2 className="h-8 w-8 animate-spin" />
          <p>Loading results...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-6xl px-6 py-8">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-bold">스캔 결과 목록</h2>
          <p className="text-sm text-slate-600 mt-1">이전 스캔 결과를 선택하세요</p>
        </div>
        <button
          onClick={onBack}
          className="inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-sm hover:bg-slate-50"
        >
          <XCircle className="h-4 w-4" /> 돌아가기
        </button>
      </div>

      {error && (
        <div className="mb-4 rounded-lg border border-rose-200 bg-rose-50 p-3 text-rose-700">
          {error}
        </div>
      )}

      {results.length === 0 ? (
        <div className="rounded-xl border border-slate-200 bg-white p-6 text-center text-slate-600">
          저장된 스캔 결과가 없습니다.
        </div>
      ) : (
        <div className="grid gap-3">
          {results.map((result) => (
            <button
              key={result.filename}
              onClick={() => handleSelectResult(result.filename)}
              className="rounded-xl border border-slate-200 bg-white p-4 text-left hover:bg-slate-50 flex items-center justify-between"
            >
              <div>
                <div className="font-medium">{result.filename}</div>
                <div className="text-xs text-slate-500 mt-1">
                  수정됨: {new Date(result.modified * 1000).toLocaleString('ko-KR')}
                </div>
              </div>
              <div className="text-xs text-slate-500">
                {(result.size / 1024).toFixed(1)} KB
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function ReportView({ data, onReset }) {
  const { findings = [], tools = [], target, startedAt, finishedAt } = data || {};

  // Filter states
  const [severityFilter, setSeverityFilter] = useState('all');
  const [toolFilter, setToolFilter] = useState('all');
  const [endpointFilter, setEndpointFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [groupByEndpoint, setGroupByEndpoint] = useState(false);

  // Get unique endpoints
  const endpoints = useMemo(() => {
    return Array.from(new Set(findings.map(f => f.endpoint).filter(Boolean)));
  }, [findings]);

  // Apply filters
  const filteredFindings = useMemo(() => {
    return findings.filter(f => {
      if (severityFilter !== 'all' && f.severity !== severityFilter) return false;
      if (toolFilter !== 'all' && f.tool !== toolFilter) return false;
      if (endpointFilter !== 'all' && f.endpoint !== endpointFilter) return false;
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        return (
          f.title?.toLowerCase().includes(query) ||
          f.description?.toLowerCase().includes(query) ||
          f.endpoint?.toLowerCase().includes(query)
        );
      }
      return true;
    });
  }, [findings, severityFilter, toolFilter, endpointFilter, searchQuery]);

  // Group by endpoint
  const groupedFindings = useMemo(() => {
    if (!groupByEndpoint) return { all: filteredFindings };

    return filteredFindings.reduce((acc, f) => {
      const key = f.endpoint || 'Unknown';
      if (!acc[key]) acc[key] = [];
      acc[key].push(f);
      return acc;
    }, {});
  }, [filteredFindings, groupByEndpoint]);

  const counts = useMemo(() => {
    const c = { total: filteredFindings.length };
    SEVERITY_ORDER.forEach((s) => (c[s] = filteredFindings.filter((f) => f.severity === s).length));
    return c;
  }, [filteredFindings]);

  function downloadFile(filename, text) {
    const blob = new Blob([text], { type: "application/json;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  function toCSV(findings) {
    function esc(s) {
      return '"' + String(s == null ? "" : s).replaceAll('"', '""') + '"';
    }
    const headers = [
      "tool",
      "severity",
      "title",
      "endpoint",
      "method",
      "cwe",
      "cvss",
      "evidence",
    ];
    const rows = findings.map((f) =>
      [
        f.tool,
        f.severity,
        f.title,
        f.endpoint,
        f.method,
        f.cwe,
        f.cvss,
        f.evidence,
      ].map(esc).join(",")
    );
    return [headers.join(","), ...rows].join("\n");
  }

  function exportJSON() {
    downloadFile("hacklipse-findings.json", JSON.stringify(findings, null, 2));
  }

  function exportCSV() {
    const csv = toCSV(findings);
    downloadFile("hacklipse-findings.csv", csv);
  }

  return (
    <div className="mx-auto max-w-6xl px-6 py-8">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-bold">진단 보고서</h2>
          <p className="text-sm text-slate-600 mt-1">
            대상: <span className="font-medium">{target}</span> · 툴: {tools.join(", ") || "-"}
          </p>
          <p className="text-xs text-slate-500">시작: {startedAt || "-"} · 종료: {finishedAt || "-"}</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={exportCSV} className="inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-sm">
            <Download className="h-4 w-4" /> CSV
          </button>
          <button onClick={exportJSON} className="inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-sm">
            <Download className="h-4 w-4" /> JSON
          </button>
          <button onClick={onReset} className="inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-sm">
            <XCircle className="h-4 w-4" /> 새 스캔
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 lg:grid-cols-6 gap-3 mb-8">
        <Stat icon={Bug} label="총 이슈" value={counts.total} />
        <Stat icon={ShieldAlert} label="Critical" value={counts.critical} tone="bg-red-100" />
        <Stat icon={ShieldAlert} label="High" value={counts.high} tone="bg-orange-100" />
        <Stat icon={ShieldAlert} label="Medium" value={counts.medium} tone="bg-amber-100" />
        <Stat icon={ShieldCheck} label="Low" value={counts.low} tone="bg-emerald-100" />
        <Stat icon={ShieldCheck} label="Info" value={counts.info} tone="bg-slate-100" />
      </div>

      {/* Filters */}
      <div className="mb-6 space-y-4">
        {/* Search */}
        <div className="relative">
          <SearchIcon className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search findings..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 rounded-lg border border-slate-200 focus:outline-none focus:ring-2 ring-slate-300"
          />
        </div>

        {/* Filter Bar */}
        <div className="flex flex-wrap gap-3 items-center">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="rounded-lg border px-3 py-2 text-sm"
          >
            <option value="all">All Severities</option>
            {SEVERITY_ORDER.map(s => (
              <option key={s} value={s}>{s.toUpperCase()}</option>
            ))}
          </select>

          <select
            value={toolFilter}
            onChange={(e) => setToolFilter(e.target.value)}
            className="rounded-lg border px-3 py-2 text-sm"
          >
            <option value="all">All Tools</option>
            {tools.map(t => (
              <option key={t} value={t}>{t.toUpperCase()}</option>
            ))}
          </select>

          <select
            value={endpointFilter}
            onChange={(e) => setEndpointFilter(e.target.value)}
            className="rounded-lg border px-3 py-2 text-sm flex-1"
          >
            <option value="all">All Endpoints</option>
            {endpoints.map(ep => (
              <option key={ep} value={ep}>{ep}</option>
            ))}
          </select>

          <button
            onClick={() => setGroupByEndpoint(!groupByEndpoint)}
            className={classNames(
              "px-3 py-2 rounded-lg text-sm",
              groupByEndpoint
                ? "bg-slate-900 text-white"
                : "border border-slate-200 hover:bg-slate-50"
            )}
          >
            Group by Endpoint
          </button>
        </div>
      </div>

      {/* Findings Display */}
      <div className="space-y-6">
        {Object.entries(groupedFindings).map(([endpoint, endpointFindings]) => (
          <div key={endpoint}>
            {groupByEndpoint && (
              <div className="mb-3">
                <div className="flex items-center gap-2 mb-2">
                  <Globe className="h-4 w-4 text-slate-600" />
                  <span className="text-sm font-medium text-slate-700">
                    {endpointFindings.length} finding{endpointFindings.length !== 1 ? 's' : ''}
                  </span>
                </div>
                <div className="bg-slate-50 rounded-lg p-3 border border-slate-200">
                  <code className="text-sm font-mono text-slate-800 break-all">{endpoint}</code>
                </div>
              </div>
            )}
            <div className="space-y-3">
              {endpointFindings.map((f) => (
                <FindingCard key={f.id} f={f} showEndpointGroup={!groupByEndpoint} />
              ))}
            </div>
          </div>
        ))}

        {filteredFindings.length === 0 && (
          <div className="rounded-xl border border-slate-200 bg-white p-6 text-center text-slate-600">
            No findings match your filters.
          </div>
        )}
      </div>
    </div>
  );
}

export default function HacklipseApp() {
  const [phase, setPhase] = useState("form"); // form | scanning | report | results-list
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  async function handleSubmit(url, extras) {
    setError(null);
    setPhase("scanning");
    try {
      const payload = await fetchScanResults(url, extras);
      setData(payload);
      setPhase("report");

      // 스캔 완료 후 최신 결과 로드 시도 (선택적)
      try {
        const res = await fetch(`${API_BASE_URL}/api/results`);
        if (res.ok) {
          const results = await res.json();
          if (results.results && results.results.length > 0) {
            // 최신 결과가 있으면 자동으로 로드
            const latestFile = results.results[0].filename;
            const latestRes = await fetch(`${API_BASE_URL}/api/results/${latestFile}`);
            if (latestRes.ok) {
              const latestData = await latestRes.json();
              setData(latestData);
            }
          }
        }
      } catch (e) {
        // 최신 결과 로드 실패해도 기존 페이로드 사용
        console.log('Failed to load latest result:', e);
      }
    } catch (e) {
      setError("스캔 결과를 불러오는 데 실패했습니다.");
      setPhase("form");
    }
  }

  function reset() {
    setPhase("form");
    setData(null);
    setError(null);
  }

  function showResultsList() {
    setPhase("results-list");
  }

  function handleSelectResult(resultData) {
    setData(resultData);
    setPhase("report");
  }

  return (
    <div className="min-h-screen bg-gradient-to-b from-slate-50 to-white">
      <Header onHomeClick={reset} />

      <main className="mx-auto max-w-6xl px-6">
        <AnimatePresence mode="wait">
          {phase === "form" && (
            <motion.div key="form" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
              <div className="text-center mt-12 mb-6">
                <h1 className="text-3xl font-extrabold tracking-tight">Secure AI Project</h1>
              </div>
              {error && (
                <div className="mb-4 rounded-lg border border-rose-200 bg-rose-50 p-3 text-rose-700">{error}</div>
              )}
              <UrlForm onSubmit={handleSubmit} />

              {/* 이전 결과 보기 버튼 */}
              <div className="mx-auto max-w-2xl mt-6 text-center">
                <button
                  onClick={showResultsList}
                  className="inline-flex items-center gap-2 rounded-lg bg-slate-100 hover:bg-slate-200 px-4 py-2 text-sm"
                >
                  <Upload className="h-4 w-4" />
                  이전 스캔 결과 보기
                </button>
              </div>

              <section className="mx-auto max-w-2xl mt-6 text-xs text-slate-500">
                <details className="rounded-lg border p-3 bg-white">
                  <summary className="cursor-pointer select-none">JSON 수동 업로드 (개발 편의)</summary>
                  <p className="mt-2 mb-2">nuclei JSONL 배열 또는 wapiti JSON을 붙여넣으면 클라이언트에서 정규화합니다.</p>
                  <textarea
                    id="manual-json"
                    className="w-full h-40 rounded-md border p-2 font-mono text-xs"
                    placeholder="여기에 JSON 붙여넣기"
                  />
                  <div className="mt-2 flex gap-2">
                    <button
                      className="inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-sm"
                      onClick={() => {
                        try {
                          const raw = document.getElementById("manual-json").value;
                          const parsed = JSON.parse(raw);
                          const normalized = normalizeMixedPayload(parsed, "manual://paste");
                          setData(normalized);
                          setPhase("report");
                        } catch (e) {
                          setError("JSON 파싱 실패: 형식을 확인하세요.");
                        }
                      }}
                    >
                      <Upload className="h-4 w-4" /> 표시하기
                    </button>
                    <button
                      className="inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-sm"
                      onClick={() => {
                        const normalized = normalizeMixedPayload(demoPayload, demoPayload.target);
                        setData(normalized);
                        setPhase("report");
                      }}
                    >
                      데모 보기
                    </button>
                  </div>
                </details>
              </section>
            </motion.div>
          )}

          {phase === "scanning" && (
            <motion.div key="loading" className="min-h-[60vh] grid place-items-center" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
              <div className="flex flex-col items-center gap-3 text-slate-700">
                <Loader2 className="h-8 w-8 animate-spin" />
                <p>스캔 결과 정리 중…</p>
              </div>
            </motion.div>
          )}

          {phase === "report" && (
            <motion.div key="report" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
              <ReportView data={data} onReset={reset} />
            </motion.div>
          )}

          {phase === "results-list" && (
            <motion.div key="results-list" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
              <ResultsListView onSelectResult={handleSelectResult} onBack={reset} />
            </motion.div>
          )}
        </AnimatePresence>
      </main>

      <footer className="mx-auto max-w-6xl px-6 py-10 text-xs text-slate-500">
        © {new Date().getFullYear()} Hacklipse. For internal testing only.
      </footer>
    </div>
  );
}
