import React, { useMemo, useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useLocation, useNavigate } from "react-router-dom";
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
  Sparkles,
  FileText,
} from "lucide-react";
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import rehypeHighlight from 'rehype-highlight';
import rehypeRaw from 'rehype-raw';
import 'highlight.js/styles/github-dark.css';

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || `http://${window.location.hostname}:3000`;
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

// Demo data for development testing
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
        // Fallback to GET on failure
      }
    }

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

function normalizeEndpoint(url) {
  if (!url) return url;
  return url.split('?')[0].split('#')[0];
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
        cwe: (info.tags || "").split(",").find((t) => t.trim().toLowerCase().startsWith("cwe-")) || undefined,
        cvss: info.cvssScore || undefined,
        evidence: item["matcher-name"] || (item["extracted-results"] || []).join(", "),
        references: Array.isArray(info.reference) ? info.reference : info.reference ? [info.reference] : [],
      });
    });
  }

  if (raw && raw.vulnerabilities) {
    raw.vulnerabilities.forEach((v) => {
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
// ------------------------------ UI Components ------------------------------ //

function Header({ onHomeClick }) {
  return (
    <header className="w-full border-b border-slate-200/60 bg-white/70 backdrop-blur sticky top-0 z-20">
      <div className="mx-auto max-w-6xl px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
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
            <div className="text-xs text-slate-500 flex items-center gap-2 flex-wrap min-w-0">
              <span className="px-2 py-0.5 bg-slate-100 rounded flex-shrink-0">{f.tool.toUpperCase()}</span>
              {f.category && <span className="flex-shrink-0">· {f.category}</span>}
              {f.method && <span className="flex-shrink-0">· {f.method}</span>}
              {showEndpointGroup && <span className="truncate max-w-[250px] inline-block" title={f.endpoint}>· {f.endpoint}</span>}
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
              {f.endpoint && (
                <div className="bg-slate-50 rounded-lg p-3">
                  <div className="text-xs font-medium text-slate-600 mb-1">Endpoint</div>
                  <div className="text-sm font-mono break-all">{f.endpoint}</div>
                </div>
              )}

              {f.fullUrl && f.fullUrl !== f.endpoint && (
                <div className="bg-amber-50 rounded-lg p-3 border border-amber-200">
                  <div className="text-xs font-medium text-amber-700 mb-1">Full URL (with payload)</div>
                  <div className="text-sm font-mono break-all text-amber-900">{f.fullUrl}</div>
                </div>
              )}

              {f.description && (
                <div>
                  <div className="text-xs font-medium text-slate-600 mb-1">Description</div>
                  <p className="text-sm text-slate-700">{f.description}</p>
                </div>
              )}

              {f.impact && f.impact !== 'N/A' && (
                <div>
                  <div className="text-xs font-medium text-slate-600 mb-1">Impact</div>
                  <p className="text-sm text-slate-700">{f.impact}</p>
                </div>
              )}

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

              {f.evidence && (
                <div>
                  <div className="text-xs font-medium text-slate-600 mb-1">Evidence</div>
                  <p className="text-sm text-slate-700">{f.evidence}</p>
                </div>
              )}

              {f.recommendation && (
                <div>
                  <div className="text-xs font-medium text-slate-600 mb-1">Recommendation</div>
                  <p className="text-sm text-slate-700">{f.recommendation}</p>
                </div>
              )}

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
      onSelectResult(data, filename);
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

// AI 보고서 뷰 컴포넌트
function AiReportView({ markdown, onBack }) {
  const [copied, setCopied] = useState(false);

  function downloadMarkdown() {
    const blob = new Blob([markdown], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `hacklipse-ai-report-${Date.now()}.md`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  function copyToClipboard() {
    navigator.clipboard.writeText(markdown);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="mx-auto max-w-5xl px-6 py-8">
      {/* 헤더 */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-gradient-to-r from-purple-500 to-indigo-500 rounded-lg">
            <Sparkles className="h-6 w-6 text-white" />
          </div>
          <div>
            <h2 className="text-2xl font-bold">AI 보안 진단 보고서</h2>
            <p className="text-sm text-slate-600 mt-1">
              Powered by Google Gemini
            </p>
          </div>
        </div>

        {/* 액션 버튼들 */}
        <div className="flex items-center gap-2">
          <button
            onClick={copyToClipboard}
            className="inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-sm hover:bg-slate-50"
          >
            {copied ? (
              <>
                <Check className="h-4 w-4" /> 복사됨!
              </>
            ) : (
              <>
                <Copy className="h-4 w-4" /> 복사
              </>
            )}
          </button>

          <button
            onClick={downloadMarkdown}
            className="inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-sm hover:bg-slate-50"
          >
            <Download className="h-4 w-4" /> 다운로드
          </button>

          <button
            onClick={onBack}
            className="inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-sm hover:bg-slate-50"
          >
            <XCircle className="h-4 w-4" /> 돌아가기
          </button>
        </div>
      </div>

      {/* 마크다운 렌더링 */}
      <div className="rounded-2xl border border-slate-200 bg-white shadow-sm overflow-hidden">
        <div className="prose prose-slate max-w-none p-8
                        prose-headings:font-bold
                        prose-h1:text-3xl prose-h2:text-2xl prose-h3:text-xl
                        prose-a:text-blue-600 hover:prose-a:text-blue-800
                        prose-code:text-sm prose-code:bg-slate-100 prose-code:px-1 prose-code:py-0.5 prose-code:rounded
                        prose-pre:bg-slate-900 prose-pre:text-slate-100
                        prose-table:border-collapse prose-th:border prose-td:border">
          <ReactMarkdown
            remarkPlugins={[remarkGfm]}
            rehypePlugins={[rehypeHighlight, rehypeRaw]}
            components={{
              h1: ({node, className, ...props}) => (
                <h1
                  className={classNames("text-3xl font-bold mt-6 mb-3", className)}
                  {...props}
                />
              ),
              h2: ({node, className, ...props}) => (
                <h2
                  className={classNames("text-2xl font-semibold mt-5 mb-2", className)}
                  {...props}
                />
              ),
              h3: ({node, className, ...props}) => (
                <h3
                  className={classNames("text-xl font-semibold mt-4 mb-2", className)}
                  {...props}
                />
              ),
              // 테이블 스타일링
              table: ({node, ...props}) => (
                <div className="overflow-x-auto my-4">
                  <table className="min-w-full divide-y divide-slate-200" {...props} />
                </div>
              ),
              th: ({node, ...props}) => (
                <th className="px-4 py-2 bg-slate-100 text-left text-sm font-semibold" {...props} />
              ),
              td: ({node, ...props}) => (
                <td className="px-4 py-2 border-t text-sm" {...props} />
              ),
              // 코드 블록
              code: ({node, inline, ...props}) => (
                inline
                  ? <code className="bg-slate-100 px-1.5 py-0.5 rounded text-sm" {...props} />
                  : <code {...props} />
              ),
              // 링크는 새 탭에서 열기
              a: ({node, ...props}) => (
                <a {...props} target="_blank" rel="noopener noreferrer" />
              ),
            }}
          >
            {markdown}
          </ReactMarkdown>
        </div>
      </div>
    </div>
  );
}

function ReportView({ data, noResults, resultFile, onReset }) {
  const { findings = [], tools = [], target, startedAt, finishedAt } = data || {};

  // Filter states
  const [severityFilter, setSeverityFilter] = useState('all');
  const [toolFilter, setToolFilter] = useState('all');
  const [endpointFilter, setEndpointFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [groupByEndpoint, setGroupByEndpoint] = useState(false);

  // AI 보고서 states
  const [aiReportMarkdown, setAiReportMarkdown] = useState(null);
  const [aiReportLoading, setAiReportLoading] = useState(false);
  const [aiReportError, setAiReportError] = useState(null);
  const [existingReport, setExistingReport] = useState(null); // 기존 보고서 정보
  const [checkingReport, setCheckingReport] = useState(true); // 보고서 확인 중

  const reportTimestamp = useMemo(() => {
    if (!resultFile) return null;
    const match = resultFile.match(/_(\d{8}_\d{6})\.json$/);
    return match ? match[1] : null;
  }, [resultFile]);

  // 컴포넌트 마운트 시 기존 보고서 확인
  React.useEffect(() => {
    async function checkExistingReport() {
      try {
        setCheckingReport(true);

        // target에서 파일명 추출
        const targetName = target
          ? (target.includes('.json')
            ? target.split(':').pop().replace('.json', '')
            : target.replace(':', '_'))
          : null;

        // 보고서 목록 조회
        const res = await fetch(`${API_BASE_URL}/api/reports`);
        if (!res.ok) throw new Error('Failed to fetch reports');

        const { reports } = await res.json();

        // 현재 target과 일치하는 보고서 찾기
        const matchingReport = reportTimestamp && targetName
          ? reports.find(r =>
            r.filename === `${targetName}_report_${reportTimestamp}.md`
          )
          : reports.find(r => targetName && r.target === targetName);

        if (matchingReport) {
          setExistingReport(matchingReport);
        }
      } catch (e) {
        console.error('보고서 확인 실패:', e);
      } finally {
        setCheckingReport(false);
      }
    }

    checkExistingReport();
  }, [target]);

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

  // 기존 보고서 불러오기 함수
  async function loadExistingReport() {
    if (!existingReport) return;

    setAiReportLoading(true);
    setAiReportError(null);

    try {
      const res = await fetch(`${API_BASE_URL}/api/reports/${existingReport.filename}`);

      if (!res.ok) {
        throw new Error('보고서를 불러올 수 없습니다.');
      }

      const result = await res.json();

      if (!result.markdown || result.markdown.trim() === '') {
        throw new Error('보고서가 비어있습니다.');
      }

      setAiReportMarkdown(result.markdown);

    } catch (e) {
      setAiReportError(e.message);
    } finally {
      setAiReportLoading(false);
    }
  }

  // AI 보고서 생성 함수
  async function generateAiReport() {
    setAiReportLoading(true);
    setAiReportError(null);

    try {
      // target에서 파일명 추출
      const filename = resultFile || (target && target.includes('.json')
        ? target.split(':').pop()
        : `${target.replace(':', '_')}.json`);
      if (!filename) {
        throw new Error('보고서 생성 대상이 없습니다.');
      }

      const res = await fetch(`${API_BASE_URL}/api/generate-report/${filename}`, {
        method: 'POST'
      });

      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.error || `서버 오류 (${res.status})`);
      }

      const result = await res.json();

      if (!result.markdown || result.markdown.trim() === '') {
        throw new Error('생성된 보고서가 비어있습니다.');
      }

      setAiReportMarkdown(result.markdown);

      // 생성 후 existingReport 상태 업데이트
      setExistingReport({
        filename: result.report_path.split('/').pop(),
        target: target.replace(':', '_')
      });

    } catch (e) {
      setAiReportError(e.message);
    } finally {
      setAiReportLoading(false);
    }
  }

  // AI 보고서 뷰 표시
  if (aiReportMarkdown) {
    return (
      <AiReportView
        markdown={aiReportMarkdown}
        onBack={() => setAiReportMarkdown(null)}
      />
    );
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
          {/* AI 보고서 버튼 - 조건부 렌더링 */}
          {checkingReport ? (
            <button
              disabled
              className="inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium bg-slate-300 text-slate-600 cursor-not-allowed"
            >
              <Loader2 className="h-4 w-4 animate-spin" />
              확인 중...
            </button>
          ) : existingReport ? (
            // 기존 보고서가 있으면 "보기" 버튼
            <button
              onClick={loadExistingReport}
              disabled={aiReportLoading}
              className={classNames(
                "inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium",
                aiReportLoading
                  ? "bg-slate-300 text-slate-600 cursor-not-allowed"
                  : "bg-slate-100 hover:bg-slate-200"
              )}
            >
              {aiReportLoading ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  로딩 중...
                </>
              ) : (
                <>
                  <FileText className="h-4 w-4" />
                  AI 보고서 보기
                </>
              )}
            </button>
          ) : (
            // 보고서가 없으면 "생성" 버튼
            <button
              onClick={generateAiReport}
              disabled={aiReportLoading}
              className={classNames(
                "inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium",
                aiReportLoading
                  ? "bg-slate-300 text-slate-600 cursor-not-allowed"
                  : "bg-slate-100 hover:bg-slate-200"
              )}
            >
              {aiReportLoading ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  생성 중...
                </>
              ) : (
                <>
                  <Sparkles className="h-4 w-4" />
                  AI 보고서 생성
                </>
              )}
            </button>
          )}

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

      {/* 에러 메시지 표시 */}
      {aiReportError && (
        <div className="mb-6 rounded-xl border border-rose-200 bg-rose-50 p-4">
          <div className="flex items-center gap-2 text-rose-700">
            <XCircle className="h-5 w-5" />
            <div>
              <div className="font-medium">AI 보고서 생성 실패</div>
              <div className="text-sm mt-1">{aiReportError}</div>
            </div>
          </div>
        </div>
      )}

      {noResults && (
        <div className="mb-6 rounded-xl border border-amber-200 bg-amber-50 p-4 text-amber-800">
          스캔 완료: 탐지된 취약점이 없습니다.
        </div>
      )}

      <div className="grid grid-cols-1 sm:grid-cols-3 lg:grid-cols-6 gap-3 mb-8">
        <Stat icon={Bug} label="총 이슈" value={counts.total} />
        <Stat icon={ShieldAlert} label="Critical" value={counts.critical} tone="bg-red-100" />
        <Stat icon={ShieldAlert} label="High" value={counts.high} tone="bg-orange-100" />
        <Stat icon={ShieldAlert} label="Medium" value={counts.medium} tone="bg-amber-100" />
        <Stat icon={ShieldCheck} label="Low" value={counts.low} tone="bg-emerald-100" />
        <Stat icon={ShieldCheck} label="Info" value={counts.info} tone="bg-slate-100" />
      </div>

      <div className="mb-6 space-y-4">
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

        {filteredFindings.length === 0 && !noResults && (
          <div className="rounded-xl border border-slate-200 bg-white p-6 text-center text-slate-600">
            No findings match your filters.
          </div>
        )}
      </div>
    </div>
  );
}

export default function HacklipseApp() {
  const [phase, setPhase] = useState("form");
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [noResults, setNoResults] = useState(false);
  const [resultFile, setResultFile] = useState(null);
  const [scanTarget, setScanTarget] = useState(null);
  const [scanStepIndex, setScanStepIndex] = useState(0);
  const [scanStatus, setScanStatus] = useState(null);
  const [scanStatusError, setScanStatusError] = useState(null);
  const navigate = useNavigate();
  const location = useLocation();
  const scanSteps = [
    {
      id: "discovery",
      label: "Discovery",
      detail: "FFUF/크롤러로 URL 수집"
    },
    {
      id: "wapiti",
      label: "Wapiti",
      detail: "Wapiti 취약점 스캔"
    },
    {
      id: "nuclei",
      label: "Nuclei",
      detail: "Nuclei 템플릿 스캔"
    },
    {
      id: "merge",
      label: "Merge",
      detail: "결과 병합 및 정리"
    }
  ];

  useEffect(() => {
    const path = location.pathname;
    if (path.startsWith("/results")) {
      setPhase("results-list");
      return;
    }

    if (path.startsWith("/report/")) {
      const filename = decodeURIComponent(path.replace("/report/", ""));
      if (filename && (filename !== resultFile || !data)) {
        (async () => {
          try {
            setError(null);
            setPhase("scanning");
            const res = await fetch(`${API_BASE_URL}/api/results/${filename}`);
            if (!res.ok) throw new Error("Failed to load result file");
            const resultData = await res.json();
            setData(resultData);
            setNoResults(false);
            setResultFile(filename);
            setScanTarget(resultData?.target || null);
            setPhase("report");
          } catch (e) {
            setError("스캔 결과를 불러오는 데 실패했습니다.");
            setPhase("form");
            navigate("/");
          }
        })();
        return;
      }
      setPhase("report");
      return;
    }

    if (path.startsWith("/report")) {
      setPhase("report");
      return;
    }

    if (path.startsWith("/scan")) {
      setPhase("scanning");
      return;
    }
    setPhase("form");
  }, [location.pathname, navigate, resultFile, data]);

  useEffect(() => {
    if (phase !== "scanning" || scanStatus?.step) {
      setScanStepIndex(0);
      return;
    }

    setScanStepIndex(0);
    const interval = setInterval(() => {
      setScanStepIndex((prev) => (prev + 1) % scanSteps.length);
    }, 12000);

    return () => clearInterval(interval);
  }, [phase, scanSteps.length, scanStatus?.step]);

  useEffect(() => {
    if (phase !== "scanning") {
      setScanStatus(null);
      setScanStatusError(null);
      return;
    }

    let active = true;

    async function pollStatus() {
      try {
        const res = await fetch(`${API_BASE_URL}/api/scan/status`);
        if (!res.ok) throw new Error("Failed to load scan status");
        const data = await res.json();
        if (!active) return;
        if (data && data.phase && data.phase !== "idle") {
          setScanStatus(data);
          setScanStatusError(null);
          if (data.target) {
            setScanTarget(data.target);
          }
          if (data.phase === "done" && data.resultFile) {
            setResultFile(data.resultFile);
            navigate(`/report/${encodeURIComponent(data.resultFile)}`);
            return;
          }
          if (data.phase === "done" && !data.resultFile) {
            setNoResults(true);
            setData({
              target: data.target,
              findings: [],
              tools: [],
              startedAt: null,
              finishedAt: null
            });
            setResultFile(null);
            setPhase("report");
            navigate("/report");
            return;
          }
          if (data.step) {
            const stepMap = {
              queued: 0,
              discovery: 0,
              wapiti: 1,
              nuclei: 2,
              filter_wapiti: 3,
              filter_nuclei: 3,
              merge: 3,
              cleanup: 3,
              complete: 3
            };
            const nextIndex = stepMap[data.step] ?? 0;
            setScanStepIndex(nextIndex);
          }
        }
      } catch (e) {
        if (!active) return;
        setScanStatusError("진행 상태를 불러올 수 없습니다.");
      }
    }

    pollStatus();
    const interval = setInterval(pollStatus, 3000);
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, [phase]);

  async function handleSubmit(url, extras) {
    setError(null);
    setNoResults(false);
    setPhase("scanning");
    setResultFile(null);
    setScanTarget(url);
    navigate("/scan");
    try {
      const payload = await fetchScanResults(url, extras);
      const hasFindingsArray = Array.isArray(payload?.findings);
      const isNoResults = hasFindingsArray && payload.findings.length === 0 && !payload?.resultFile;
      const hasScanMeta = payload && typeof payload === "object" && ("message" in payload || "target" in payload);
      setNoResults(isNoResults);
      setData(payload);
      if (payload?.resultFile) {
        setResultFile(payload.resultFile);
      }
      setPhase("report");
      navigate("/report");

      if (!payload || (!hasFindingsArray && !hasScanMeta)) {
        try {
          const res = await fetch(`${API_BASE_URL}/api/results`);
          if (res.ok) {
            const results = await res.json();
            if (results.results && results.results.length > 0) {
              const latestFile = results.results[0].filename;
              const latestRes = await fetch(`${API_BASE_URL}/api/results/${latestFile}`);
              if (latestRes.ok) {
                const latestData = await latestRes.json();
                setData(latestData);
                setNoResults(false);
              }
            }
          }
        } catch (e) {
          console.log('Failed to load latest result:', e);
        }
      }
    } catch (e) {
      setError("스캔 결과를 불러오는 데 실패했습니다.");
      setPhase("form");
      setResultFile(null);
      setNoResults(false);
      setScanTarget(null);
      navigate("/");
    }
  }

  function reset() {
    setPhase("form");
    setData(null);
    setError(null);
    setResultFile(null);
    setNoResults(false);
    setScanTarget(null);
    navigate("/");
  }

  function showResultsList() {
    setPhase("results-list");
    setNoResults(false);
    navigate("/results");
  }

  function handleSelectResult(resultData, filename) {
    setData(resultData);
    setNoResults(false);
    setPhase("report");
    setScanTarget(resultData?.target || null);
    if (filename) {
      setResultFile(filename);
      navigate(`/report/${encodeURIComponent(filename)}`);
    } else {
      setResultFile(null);
      navigate("/report");
    }
  }

  return (
    <div className="min-h-screen bg-white">
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
                          setNoResults(false);
                          setPhase("report");
                          setResultFile(null);
                          setScanTarget(normalized?.target || "manual://paste");
                          navigate("/report");
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
                        setNoResults(false);
                        setPhase("report");
                        setResultFile(null);
                        setScanTarget(normalized?.target || demoPayload.target);
                        navigate("/report");
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
              <div className="flex flex-col items-center gap-4 text-slate-700 w-full">
                <Loader2 className="h-8 w-8 animate-spin" />
                <p>스캔 결과 정리 중…</p>
                <div className="w-full max-w-3xl rounded-2xl border border-slate-200 bg-white p-6">
                  <div className="text-sm text-slate-600">
                    스캔 대상: <span className="font-medium text-slate-800">{scanTarget || "-"}</span>
                  </div>
                  {scanStatus?.message && (
                    <div className="mt-2 text-xs text-slate-500">
                      현재 단계: <span className="font-medium text-slate-700">{scanStatus.message}</span>
                    </div>
                  )}
                  {scanStatus?.progress?.total > 0 && (
                    <div className="mt-1 text-xs text-slate-500">
                      진행률:{" "}
                      <span className="font-medium text-slate-700">
                        {scanStatus.progress.percent ?? Math.round((scanStatus.progress.current / scanStatus.progress.total) * 100)}%
                      </span>
                      <span className="text-slate-400 ml-2">
                        ({scanStatus.progress.current}/{scanStatus.progress.total})
                      </span>
                    </div>
                  )}
                  {scanStatus?.updatedAt && (
                    <div className="mt-1 text-[11px] text-slate-400">
                      마지막 업데이트: {new Date(scanStatus.updatedAt * 1000).toLocaleString("ko-KR")}
                    </div>
                  )}
                  {scanStatusError && (
                    <div className="mt-3 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-700">
                      {scanStatusError}
                    </div>
                  )}
                  <div className="mt-4 space-y-3">
                    {scanSteps.map((step, index) => (
                      <div key={step.id} className="flex items-start gap-3">
                        <div
                          className={classNames(
                            "mt-1 h-2 w-2 rounded-full",
                            index < scanStepIndex
                              ? "bg-emerald-500"
                              : index === scanStepIndex
                              ? "bg-sky-500"
                              : "bg-slate-300"
                          )}
                        />
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-semibold">{step.label}</span>
                            <span className="text-xs text-slate-500">
                              {index < scanStepIndex ? "완료" : index === scanStepIndex ? "진행 중" : "대기"}
                            </span>
                          </div>
                          <div className="text-xs text-slate-500 mt-1">{step.detail}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                  <p className="mt-4 text-xs text-slate-400">
                    단계 표시는 서버 상태 기준으로 표시됩니다.
                  </p>
                </div>
              </div>
            </motion.div>
          )}

          {phase === "report" && (
            <motion.div key="report" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
              <ReportView data={data} noResults={noResults} resultFile={resultFile} onReset={reset} />
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
