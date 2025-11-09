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

function normalizeMixedPayload(raw, target) {
  const findings = [];

  function push(f) {
    if (!f || !f.title) return;
    const sev = (f.severity || "info").toLowerCase();
    findings.push({
      id: f.id || `${f.tool || "unknown"}-${findings.length + 1}-${Date.now()}`,
      tool: f.tool || "unknown",
      severity: SEVERITY_ORDER.includes(sev) ? sev : "info",
      title: f.title,
      description: f.description,
      endpoint: f.endpoint,
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
function Header() {
  return (
    <header className="w-full border-b border-slate-200/60 bg-white/70 backdrop-blur sticky top-0 z-20">
      <div className="mx-auto max-w-6xl px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          {/* 로고 이미지 */}
          <img
            src="/logo.png"
            alt="Hacklipse"
            className="h-7 w-auto"
            draggable={false}
          />
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

function FindingCard({ f }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="rounded-xl border border-slate-200 bg-white">
      <button
        onClick={() => setOpen(!open)}
        className="w-full text-left p-4 flex items-center justify-between"
      >
        <div className="flex items-center gap-3">
          {f.severity === "high" || f.severity === "critical" ? (
            <ShieldAlert className="h-5 w-5 text-red-600" />
          ) : (
            <ShieldCheck className="h-5 w-5 text-emerald-600" />
          )}
          <div>
            <div className="font-medium">{f.title}</div>
            <div className="text-xs text-slate-500">{f.tool.toUpperCase()} · {f.method || ""} {f.endpoint || ""}</div>
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
            className="px-4 pb-4"
          >
            {f.description && (
              <p className="mb-3 text-sm text-slate-700">{f.description}</p>
            )}
            <div className="grid gap-2 text-sm">
              {f.cwe && (
                <div className="text-slate-600"><span className="font-medium">CWE:</span> {String(f.cwe)}</div>
              )}
              {f.cvss != null && (
                <div className="text-slate-600"><span className="font-medium">CVSS:</span> {String(f.cvss)}</div>
              )}
              {f.evidence && (
                <div className="text-slate-600"><span className="font-medium">Evidence:</span> {f.evidence}</div>
              )}
              {f.recommendation && (
                <div className="text-slate-600"><span className="font-medium">Recommendation:</span> {f.recommendation}</div>
              )}
              {Array.isArray(f.references) && f.references.length > 0 && (
                <div className="text-slate-600">
                  <span className="font-medium">References:</span>
                  <ul className="list-disc pl-5">
                    {f.references.map((r, i) => (
                      <li key={i}><a className="underline hover:no-underline" href={r} target="_blank" rel="noreferrer">{r}</a></li>
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

function ReportView({ data, onReset }) {
  const { findings = [], tools = [], target, startedAt, finishedAt } = data || {};

  const counts = useMemo(() => {
    const c = { total: findings.length };
    SEVERITY_ORDER.forEach((s) => (c[s] = findings.filter((f) => f.severity === s).length));
    return c;
  }, [findings]);

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

      <div className="space-y-3">
        {findings.length === 0 && (
          <div className="rounded-xl border border-slate-200 bg-white p-6 text-slate-600">
            유효한 취약점 결과가 없습니다.
          </div>
        )}
        {findings.map((f) => (
          <FindingCard key={f.id} f={f} />
        ))}
      </div>
    </div>
  );
}

export default function HacklipseApp() {
  const [phase, setPhase] = useState("form"); // form | scanning | report
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  async function handleSubmit(url, extras) {
    setError(null);
    setPhase("scanning");
    try {
      const payload = await fetchScanResults(url, extras);
      setData(payload);
      setPhase("report");
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

  return (
    <div className="min-h-screen bg-gradient-to-b from-slate-50 to-white">
      <Header />

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
        </AnimatePresence>
      </main>

      <footer className="mx-auto max-w-6xl px-6 py-10 text-xs text-slate-500">
        © {new Date().getFullYear()} Hacklipse. For internal testing only.
      </footer>
    </div>
  );
}
