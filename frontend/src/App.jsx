import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  BarChart3,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock3,
  Code2,
  Copy,
  Download,
  Globe2,
  LayoutDashboard,
  Lock,
  LockKeyhole,
  Loader2,
  Mail,
  Palette,
  Radar,
  RefreshCw,
  Search,
  Server,
  Settings2,
  ShieldCheck,
  Sparkles,
  Target,
  Terminal,
  UserRound,
  Wifi,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { apiUrl } from "./api.js";

const STORAGE_KEY = "hit-securescan-history-v1";
const DEEP_SCAN_STORAGE_KEY = "hit-securescan-active-scan-id-v1";
const INDIA_TIMEZONE = "Asia/Kolkata";
const emptyCounts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
const severityOrder = { Critical: 0, High: 1, Medium: 2, Low: 3, Informational: 4, Info: 4 };
const defaultAccount = {
  first_name: "Ayush",
  last_name: "Rana",
  email: "ayush@example.com",
  company_name: "Hands In Technology",
  scans_left: 5,
  scans_used: 0,
  account_plan: {
    name: "Basic",
    no_of_scans_available: 5,
  },
};

function loadHistory() {
  try {
    const value = JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
    return Array.isArray(value) ? value : [];
  } catch {
    return [];
  }
}

function saveHistory(items) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(items.slice(0, 30)));
}

function normalizeUrl(value) {
  const trimmed = value.trim();
  if (!trimmed) return "";
  return /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
}

function domainFromUrl(value) {
  try {
    return new URL(value).hostname;
  } catch {
    return value.replace(/^https?:\/\//i, "").split("/")[0] || value;
  }
}

function cleanStatus(value) {
  return String(value || "Queued")
    .replace(/^[^A-Za-z]*/, "")
    .trim();
}

function formatDuration(totalSeconds) {
  const seconds = Number(totalSeconds);
  if (!Number.isFinite(seconds) || seconds < 1) return "0s";
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  if (minutes < 60) return remainder ? `${minutes}m ${remainder}s` : `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  const leftover = minutes % 60;
  return leftover ? `${hours}h ${leftover}m` : `${hours}h`;
}

function parseEnvExports(commandText) {
  const exportsMap = {};
  String(commandText || "").split("\n").forEach((line) => {
    const match = line.match(/^export\s+([A-Z0-9_]+)="([^"]*)"$/);
    if (match) exportsMap[match[1]] = match[2];
  });
  return exportsMap;
}

function formatDeepCommandPresentation(mode, commands) {
  const rawCommand = commands?.[mode] || "";
  const base = {
    primary: rawCommand,
    fallback: "",
    note: commands?.notes || "Run this from inside the project folder on the server.",
  };

  if (!["linux", "git_bash"].includes(mode)) return base;

  const env = parseEnvExports(rawCommand);
  if (!env.SCAN_ID) return base;

  const targetLine = env.SCAN_TARGET_URL ? `export SCAN_TARGET_URL="${env.SCAN_TARGET_URL}"\n` : "";
  return {
    primary:
      `export SCAN_ID="${env.SCAN_ID}"\n` +
      targetLine +
      `bash <(curl -fsSL ${apiUrl("/api/deep-scan/run.sh")})`,
    fallback: rawCommand,
    note: "Use this on a Linux server, SSH terminal, or Git Bash. Open the alternative method if curl is unavailable.",
  };
}

function severityClass(severity) {
  return String(severity || "Info").toLowerCase();
}

function getFindingCounts(report) {
  const counts = { ...emptyCounts };
  const summaryCounts = report?.executive_summary?.finding_counts;

  if (summaryCounts && typeof summaryCounts === "object") {
    Object.entries(summaryCounts).forEach(([key, value]) => {
      const normalized = key === "Informational" ? "Info" : key;
      if (normalized in counts) counts[normalized] += Number(value) || 0;
    });
    return counts;
  }

  const items = report?.assessment_items || [];
  items.forEach((item) => {
    const severity = item.severity === "Informational" ? "Info" : item.severity || "Info";
    if (severity in counts) counts[severity] += 1;
  });
  return counts;
}

function riskFromCounts(counts) {
  if (counts.Critical) return "Critical";
  if (counts.High) return "High";
  if (counts.Medium) return "Medium";
  if (counts.Low) return "Low";
  return "Info";
}

function scoreFromCounts(counts) {
  const weighted =
    counts.Critical * 10 +
    counts.High * 8 +
    counts.Medium * 5 +
    counts.Low * 2 +
    counts.Info * 0.5;
  const total = Object.values(counts).reduce((sum, value) => sum + value, 0);
  if (!total) return 0;
  return Math.min(10, Math.max(0, Number((weighted / total).toFixed(1))));
}

function buildHistoryItem(report) {
  const meta = report.scan_metadata || {};
  const counts = getFindingCounts(report);
  const total = Object.values(counts).reduce((sum, value) => sum + value, 0);
  return {
    id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
    target: meta.target || "Unknown target",
    domain: domainFromUrl(meta.target || "Unknown target"),
    scannedAt: meta.scan_completed_at || formatDateTime(new Date()),
    elapsedSeconds: meta.elapsed_seconds || 0,
    counts,
    total,
    risk: report.executive_summary?.risk_rating || riskFromCounts(counts),
    scope: report.executive_summary?.scope || {},
  };
}

function guidanceForDomain(item) {
  if (item.counts.Critical || item.counts.High) {
    return "Prioritize high-impact fixes and rescan after remediation.";
  }
  if (item.counts.Medium) {
    return "Review configuration gaps and harden browser-facing controls.";
  }
  if (item.counts.Low) {
    return "Track low-risk exposure and keep monitoring for regressions.";
  }
  return "No urgent action from saved scans. Keep a regular scan cadence.";
}

function buildDomainOverview(history) {
  const byDomain = new Map();

  history.forEach((item) => {
    const existing = byDomain.get(item.domain) || {
      domain: item.domain,
      target: item.target,
      scans: 0,
      total: 0,
      counts: { ...emptyCounts },
      latest: item.scannedAt,
    };

    existing.scans += 1;
    existing.total += item.total || 0;
    Object.keys(emptyCounts).forEach((key) => {
      existing.counts[key] += item.counts?.[key] || 0;
    });
    existing.latest = item.scannedAt || existing.latest;
    byDomain.set(item.domain, existing);
  });

  return Array.from(byDomain.values())
    .map((item) => {
      const score = scoreFromCounts(item.counts);
      return {
        ...item,
        score,
        protection: Math.max(0, Math.round(100 - score * 10)),
        risk: riskFromCounts(item.counts),
        guidance: guidanceForDomain(item),
      };
    })
    .sort((a, b) => b.score - a.score || b.total - a.total);
}

function App() {
  const [activeView, setActiveView] = useState("dashboard");
  const [history, setHistory] = useState(loadHistory);
  const [recentScans, setRecentScans] = useState([]);
  const [dashboardSummary, setDashboardSummary] = useState(null);
  const [account, setAccount] = useState(defaultAccount);
  const [target, setTarget] = useState("");
  const [scanId, setScanId] = useState("");
  const [liveStatus, setLiveStatus] = useState(null);
  const [report, setReport] = useState(null);
  const [error, setError] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const pollRef = useRef(null);

  const totals = useMemo(() => {
    if (dashboardSummary) {
      const vulnerabilityCounts = dashboardSummary.vulnerabilities || {};
      return {
        scans: dashboardSummary.scans?.total || 0,
        domains: dashboardSummary.domains?.total || 0,
        vulnerabilities: dashboardSummary.vulnerabilities?.total || 0,
        processing: dashboardSummary.scans?.processing || 0,
        failed: dashboardSummary.scans?.failed || 0,
        byType: dashboardSummary.scans?.by_type || {},
        counts: {
          Critical: vulnerabilityCounts.critical || 0,
          High: vulnerabilityCounts.high || 0,
          Medium: vulnerabilityCounts.medium || 0,
          Low: vulnerabilityCounts.low || 0,
          Info: vulnerabilityCounts.info || 0,
        },
        risk: dashboardSummary.risk || "Info",
      };
    }
    const counts = { ...emptyCounts };
    let vulnerabilities = 0;
    history.forEach((item) => {
      vulnerabilities += item.total || 0;
      Object.keys(counts).forEach((key) => {
        counts[key] += item.counts?.[key] || 0;
      });
    });
    return {
      scans: history.length,
      domains: new Set(history.map((item) => item.domain)).size,
      vulnerabilities,
      counts,
      risk: riskFromCounts(counts),
    };
  }, [history, dashboardSummary]);

  useEffect(() => {
    loadAccount();
    loadDashboardSummary();
    loadRecentScans();
    return () => {
      if (pollRef.current) window.clearInterval(pollRef.current);
    };
  }, []);

  async function loadAccount() {
    try {
      const response = await fetch(apiUrl("/api/me"));
      if (!response.ok) return;
      const payload = await response.json();
      setAccount({ ...defaultAccount, ...payload });
    } catch {
      setAccount((current) => current || defaultAccount);
    }
  }

  async function loadRecentScans() {
    try {
      const response = await fetch(apiUrl("/api/scans?limit=12"));
      if (!response.ok) return;
      const payload = await response.json();
      setRecentScans(Array.isArray(payload) ? payload : []);
    } catch {
      setRecentScans([]);
    }
  }

  async function loadDashboardSummary() {
    try {
      const response = await fetch(apiUrl("/api/dashboard/summary"));
      if (!response.ok) return;
      const payload = await response.json();
      setDashboardSummary(payload);
      if (Array.isArray(payload.recent_scans)) setRecentScans(payload.recent_scans);
    } catch {
      setDashboardSummary(null);
    }
  }

  function persistReport(nextReport) {
    const item = buildHistoryItem(nextReport);
    const nextHistory = [item, ...history.filter((entry) => entry.target !== item.target)].slice(0, 30);
    setHistory(nextHistory);
    saveHistory(nextHistory);
  }

  async function startScan(event, overrideTarget) {
    event?.preventDefault();
    const url = normalizeUrl(overrideTarget || target);
    if (!url) return;

    if (pollRef.current) window.clearInterval(pollRef.current);
    setTarget(url);
    setActiveView("scan");
    setError("");
    setReport(null);
    setScanId("");
    setIsScanning(true);
    setLiveStatus({
      status: "Queued",
      current_step: "Queued",
      live_metrics: {},
      events_log: { recent: [] },
      progress: { percent: 4 },
      timing: {},
    });

    try {
      const response = await fetch(apiUrl("/api/scan"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url,
          headless: true,
          max_pages: 20,
          max_depth: 2,
        }),
      });

      if (!response.ok) throw new Error(await response.text());
      const job = await response.json();
      setScanId(job.scan_id);
      await loadAccount();
      await loadDashboardSummary();
      await loadRecentScans();
      pollRef.current = window.setInterval(() => pollScan(job.scan_id), 1800);
      await pollScan(job.scan_id);
    } catch (scanError) {
      setIsScanning(false);
      setError("Could not start the scan. Confirm the backend service is reachable.");
      setLiveStatus((current) => ({
        ...(current || {}),
        status: "Failed",
        current_step: "Scan failed",
        error: scanError.message,
      }));
    }
  }

  async function pollScan(id) {
    try {
      const response = await fetch(apiUrl(`/api/scan/status/${id}?readable=true`));
      if (!response.ok) throw new Error(await response.text());
      const payload = await response.json();

      if (payload.scan_metadata && payload.executive_summary) {
        if (pollRef.current) window.clearInterval(pollRef.current);
        pollRef.current = null;
        setIsScanning(false);
        setReport(payload);
        setLiveStatus((current) => ({
          ...(current || {}),
          status: "Completed",
          current_step: "Scan complete",
          progress: { percent: 100 },
          timing: {
            ...(current?.timing || {}),
            elapsed_seconds: payload.scan_metadata?.elapsed_seconds,
            estimated_remaining_seconds: 0,
          },
        }));
        await loadAccount();
        await loadDashboardSummary();
        await loadRecentScans();
        persistReport(payload);
        return;
      }

      setLiveStatus(payload);
    } catch (pollError) {
      if (pollRef.current) window.clearInterval(pollRef.current);
      pollRef.current = null;
      setIsScanning(false);
      setError("Live polling stopped. The backend may have restarted or the scan ID is no longer available.");
      setLiveStatus((current) => ({
        ...(current || {}),
        status: "Failed",
        current_step: "Polling failed",
        error: pollError.message,
      }));
    }
  }

  async function downloadPdf() {
    if (!scanId) return;
    const response = await fetch(apiUrl(`/api/scan/status/${scanId}?pdf=true`));
    if (!response.ok) {
      setError("PDF is not ready yet.");
      return;
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${domainFromUrl(target)}-security-report.pdf`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  if (activeView === "pricing") {
    return <PricingPage onBack={() => setActiveView("dashboard")} />;
  }

  return (
    <div className="app-shell">
      <Sidebar activeView={activeView} setActiveView={setActiveView} account={account} />
      <main className="workspace">
        <Topbar target={target} setTarget={setTarget} account={account} openPricing={() => setActiveView("pricing")} />
        {activeView === "dashboard" ? (
          <Dashboard
            totals={totals}
            history={history}
            dashboardSummary={dashboardSummary}
            recentScans={recentScans}
            onScan={(value) => startScan(null, value)}
            openScan={() => setActiveView("scan")}
            account={account}
          />
        ) : activeView === "monitoring" ? (
          <ActiveMonitoring openPricing={() => setActiveView("pricing")} />
        ) : activeView === "deep-scan" ? (
          <DeepScan openPricing={() => setActiveView("pricing")} />
        ) : activeView === "vulnerabilities" ? (
          <VulnerabilitiesPage />
        ) : (
          <ScanView
            target={target}
            setTarget={setTarget}
            startScan={startScan}
            isScanning={isScanning}
            liveStatus={liveStatus}
            report={report}
            error={error}
            downloadPdf={downloadPdf}
            scanId={scanId}
            history={history}
            recentScans={recentScans}
            onScan={(value) => startScan(null, value)}
          />
        )}
      </main>
    </div>
  );
}

function Sidebar({ activeView, setActiveView, account }) {
  const [accountOpen, setAccountOpen] = useState(false);
  const accountName = `${account?.first_name || "Ayush"} ${account?.last_name || "Rana"}`.trim();
  const planName = account?.account_plan?.name || "Basic";

  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-mark" aria-hidden="true">
          <Globe2 size={21} />
        </div>
        <div>
          <strong>Security Tool</strong>
          <span>Powered by Hands In Technology</span>
        </div>
      </div>
      <nav className="nav-list">
        <button className={activeView === "dashboard" ? "active" : ""} onClick={() => setActiveView("dashboard")}>
          <LayoutDashboard size={18} /> Dashboard
        </button>
        <button className={activeView === "scan" ? "active" : ""} onClick={() => setActiveView("scan")}>
          <Radar size={18} /> Scan a domain
        </button>
        <button className={activeView === "monitoring" ? "active" : ""} onClick={() => setActiveView("monitoring")}>
          <Wifi size={18} /> Active Monitoring
        </button>
        <button className={activeView === "deep-scan" ? "active" : ""} onClick={() => setActiveView("deep-scan")}>
          <Terminal size={18} /> Deep Scan
        </button>
        <button className={activeView === "vulnerabilities" ? "active" : ""} onClick={() => setActiveView("vulnerabilities")}>
          <BarChart3 size={18} /> Vulnerabilities
        </button>
        <button type="button">
          <Settings2 size={18} /> Settings
        </button>
      </nav>

      <div className="account-wrap">
        <button className="account-card" type="button" onClick={() => setAccountOpen((value) => !value)}>
          <div className="avatar">AR</div>
          <div>
            <strong>{accountName}</strong>
            <span>{planName} Plan</span>
          </div>
        </button>
        {accountOpen ? (
          <div className="account-menu">
            <button type="button">
              <UserRound size={16} />
              <span>Profile settings</span>
            </button>
            <button type="button">
              <Palette size={16} />
              <span>Personalisation</span>
            </button>
            <button type="button">
              <LockKeyhole size={16} />
              <span>Security preferences</span>
            </button>
            <button type="button">
              <Settings2 size={16} />
              <span>Workspace settings</span>
            </button>
            <button className="advanced-upgrade" type="button" onClick={() => setActiveView("pricing")}>
              <Sparkles size={16} />
              <span>Upgrade plan</span>
            </button>
          </div>
        ) : null}
      </div>
    </aside>
  );
}

function DeepScan() {
  const [websiteUrl, setWebsiteUrl] = useState("");
  const [scanSession, setScanSession] = useState(null);
  const [deepReport, setDeepReport] = useState(null);
  const [commandMode, setCommandMode] = useState("linux");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [copiedFallback, setCopiedFallback] = useState(false);
  const deepPollRef = useRef(null);

  useEffect(() => {
    const savedScanId = localStorage.getItem(DEEP_SCAN_STORAGE_KEY);
    if (savedScanId) startDeepPolling(savedScanId);
    return () => {
      if (deepPollRef.current) window.clearInterval(deepPollRef.current);
    };
  }, []);

  const commands = scanSession?.commands || {};
  const commandModes = [
    ["linux", "Linux"],
    ["git_bash", "Git Bash"],
    ["powershell", "PowerShell"],
    ["cmd", "CMD"],
  ].filter(([key]) => commands[key]);
  const activeCommand = commands[commandMode] || commands.linux || "";
  const commandPresentation = formatDeepCommandPresentation(commandMode, commands);
  const report = deepReport || scanSession?.report;
  const reportSummary = scanSession?.report_summary || {};
  const summary = report?.summary || reportSummary.summary || {};
  const codebase = report?.codebase || {};
  const findings = report?.findings || [];
  const reportMeta = report || reportSummary;

  async function createDeepScan(event) {
    event.preventDefault();
    setError("");
    setLoading(true);
    setDeepReport(null);

    try {
      const response = await fetch(apiUrl("/api/deep-scan/api/scans"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ website_url: normalizeUrl(websiteUrl) }),
      });
      if (!response.ok) throw new Error(await response.text());
      const payload = await response.json();
      setScanSession(payload.scan);
      localStorage.setItem(DEEP_SCAN_STORAGE_KEY, payload.scan.id);
      setCommandMode(payload.scan?.commands?.linux ? "linux" : Object.keys(payload.scan?.commands || {})[0] || "linux");
      startDeepPolling(payload.scan.id);
    } catch (scanError) {
      setError("Could not prepare the Deep Scan command. Confirm backend_new is running and the deep-scan routes are mounted.");
    } finally {
      setLoading(false);
    }
  }

  function startDeepPolling(id) {
    if (deepPollRef.current) window.clearInterval(deepPollRef.current);
    deepPollRef.current = window.setInterval(() => fetchDeepScan(id), 4000);
    fetchDeepScan(id);
  }

  async function fetchDeepScan(id = scanSession?.id) {
    if (!id) return;
    try {
      const response = await fetch(apiUrl(`/api/deep-scan/api/scans/${encodeURIComponent(id)}`));
      if (!response.ok) throw new Error(await response.text());
      const payload = await response.json();
      setScanSession(payload);
      localStorage.setItem(DEEP_SCAN_STORAGE_KEY, payload.id || id);
      if (payload.report) setDeepReport(payload.report);
      if (["completed", "failed"].includes(String(payload.status || "").toLowerCase()) && deepPollRef.current) {
        window.clearInterval(deepPollRef.current);
        deepPollRef.current = null;
      }
    } catch (pollError) {
      setError("Could not refresh Deep Scan status. The session may no longer be available.");
      localStorage.removeItem(DEEP_SCAN_STORAGE_KEY);
      if (deepPollRef.current) window.clearInterval(deepPollRef.current);
      deepPollRef.current = null;
    }
  }

  async function copyCommand() {
    if (!commandPresentation.primary) return;
    await navigator.clipboard.writeText(commandPresentation.primary);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1400);
  }

  async function copyFallbackCommand() {
    if (!commandPresentation.fallback) return;
    await navigator.clipboard.writeText(commandPresentation.fallback);
    setCopiedFallback(true);
    window.setTimeout(() => setCopiedFallback(false), 1400);
  }

  return (
    <section className="page">
      <div className="page-heading">
        <div>
          <p className="eyebrow">Source-code security scan</p>
          <h1>Deep Scan</h1>
        </div>
        <span className={`locked-plan-pill premium deep-status ${scanSession?.status || "idle"}`}>
          <Terminal size={15} /> {scanSession?.status || "Ready"}
        </span>
      </div>

      <section className="locked-module">
        <form className="locked-hero deep-launch" onSubmit={createDeepScan}>
          <div className="locked-icon">
            <Code2 size={28} />
          </div>
          <div>
            <p className="eyebrow">Repository scanner</p>
            <h2>Prepare a scan command for the project server</h2>
            <span>
              Deep Scan reviews source files, dependency manifests, secrets, infrastructure config, CI/CD files, and static API routes from inside the client repository.
            </span>
          </div>
          <label className="deep-url-field">
            Website URL
            <input value={websiteUrl} onChange={(event) => setWebsiteUrl(event.target.value)} placeholder="https://example.com" required />
          </label>
          <button className="primary-action" type="submit" disabled={loading}>
            {loading ? <Loader2 className="spin" size={18} /> : <ArrowUpRight size={18} />}
            Prepare command
          </button>
        </form>

        <section className="panel monitoring-guide module-guide-top">
          <div className="panel-title">
            <strong>How to use Deep Scan safely</strong>
            <span>Recommended source-code scanning workflow</span>
          </div>
          <div className="guide-steps">
            <div>
              <strong>1</strong>
              <span>Run the command from the root of the repository so package files, source folders, configs, and lockfiles are visible.</span>
            </div>
            <div>
              <strong>2</strong>
              <span>Use a read-only token with repository scan permission. Do not paste production secrets into the terminal.</span>
            </div>
            <div>
              <strong>3</strong>
              <span>Review critical and high findings first, especially secrets, dependency CVEs, unsafe input handling, and auth logic.</span>
            </div>
            <div>
              <strong>4</strong>
              <span>Run Deep Scan in CI before deployment, then compare it with public URL scan results after release.</span>
            </div>
          </div>
        </section>

        {error ? <div className="error-box">{error}</div> : null}

        {scanSession ? (
          <section className="panel deep-command-panel">
            <div className="panel-title horizontal">
              <div>
                <strong>Run command</strong>
                <span>Open the project root on the server, run this command, then keep this page open for results.</span>
              </div>
              <button className="secondary-action" type="button" onClick={copyCommand}>
                <Copy size={17} /> {copied ? "Copied" : "Copy"}
              </button>
            </div>
            <div className="deep-command-tabs">
              {commandModes.map(([key, label]) => (
                <button className={commandMode === key ? "active" : ""} type="button" key={key} onClick={() => setCommandMode(key)}>
                  {label}
                </button>
              ))}
            </div>
            <pre className="monitor-script deep-command-output"><code>{commandPresentation.primary || activeCommand || "No command available for this session."}</code></pre>
            <span className="deep-command-note">{commandPresentation.note}</span>
            {commandPresentation.fallback ? (
              <details className="deep-command-fallback">
                <summary>Alternative download method</summary>
                <button className="secondary-action" type="button" onClick={copyFallbackCommand}>
                  <Copy size={17} /> {copiedFallback ? "Copied" : "Copy alternative"}
                </button>
                <pre className="monitor-script deep-command-output"><code>{commandPresentation.fallback}</code></pre>
              </details>
            ) : null}
            <div className="deep-session-strip">
              <span><strong>Scan ID</strong>{scanSession.id}</span>
              <span><strong>Last update</strong>{formatDateTime(scanSession.updated_at)}</span>
              <span><strong>Target</strong>{scanSession.website_url || "Repository root"}</span>
            </div>
          </section>
        ) : null}

        <div className="monitoring-grid deep-scan-grid">
          <article className="panel monitoring-panel">
            <div className="panel-title">
              <strong>Live scan activity</strong>
              <span>Events posted by the command running on the client server</span>
            </div>
            <div className="deep-timeline">
              {(scanSession?.events || []).length ? (
                [...scanSession.events].reverse().slice(0, 8).map((event, index) => (
                  <div className={`deep-event ${event.status || "pending"}`} key={`${event.timestamp}-${index}`}>
                    <Clock3 size={16} />
                    <div>
                      <strong>{event.message || "Scan event"}</strong>
                      <span>{event.stage || "scan"} - {event.status || "pending"} - {formatDateTime(event.timestamp)}</span>
                    </div>
                  </div>
                ))
              ) : (
                <div className="history-empty">
                  <Clock3 size={18} />
                  <span>Create a scan session to see command activity here.</span>
                </div>
              )}
            </div>
          </article>

          <article className="panel monitoring-panel">
            <div className="panel-title">
              <strong>Finding summary</strong>
              <span>Populates after the report upload finishes</span>
            </div>
            <div className="deep-summary-grid">
              <div className="critical"><span>Critical</span><strong>{summary.critical || 0}</strong></div>
              <div className="high"><span>High</span><strong>{summary.high || 0}</strong></div>
              <div className="medium"><span>Medium</span><strong>{summary.medium || 0}</strong></div>
              <div className="low"><span>Low</span><strong>{summary.low || 0}</strong></div>
              <div><span>Total</span><strong>{summary.total || findings.length || 0}</strong></div>
            </div>
            {reportMeta?.report_file || reportMeta?.generated_at ? (
              <span className="deep-report-meta">Report: {reportMeta.report_file || "uploaded"} - Generated {formatDateTime(reportMeta.generated_at)}</span>
            ) : null}
          </article>
        </div>

        {report ? <DeepScanReport report={report} codebase={codebase} findings={findings} /> : null}

      </section>
    </section>
  );
}

function formatDateTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : date.toLocaleString("en-IN", {
        timeZone: INDIA_TIMEZONE,
        year: "numeric",
        month: "short",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      });
}

function DeepScanReport({ report, codebase, findings }) {
  const categories = Object.entries(report.summary?.by_category || {}).sort((a, b) => b[1] - a[1]);
  return (
    <section className="panel deep-report-panel">
      <div className="panel-title">
        <div>
          <strong>Deep Scan report</strong>
          <span>{report.root || "Scanned repository"} - {findings.length} findings</span>
        </div>
      </div>
      <div className="deep-inventory-grid">
        <div>
          <strong>Languages</strong>
          {(codebase.languages || []).slice(0, 6).map((item) => <span key={item.name}>{item.name}: {item.files} files</span>)}
        </div>
        <div>
          <strong>Frameworks</strong>
          {(codebase.detected_frameworks || ["None detected"]).slice(0, 8).map((item) => <span key={item}>{item}</span>)}
        </div>
        <div>
          <strong>Categories</strong>
          {(categories.length ? categories : [["none", 0]]).slice(0, 8).map(([name, count]) => <span key={name}>{name}: {count}</span>)}
        </div>
      </div>
      <div className="deep-findings-list">
        {findings.slice(0, 12).map((finding, index) => (
          <article className={`deep-finding ${severityClass(finding.severity)}`} key={`${finding.file}-${finding.line}-${index}`}>
            <span>{finding.severity || "unknown"}</span>
            <div>
              <strong>{finding.title || "Security finding"}</strong>
              <small>{finding.category || "code"} - {finding.file || "unknown file"}:{finding.line || 1}</small>
              <p>{finding.remediation || finding.note || "Review the evidence and remediate in source."}</p>
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}

function CommandCard({ icon: Icon, title, subtitle, lines }) {
  return (
    <article className="panel command-card">
      <div className="panel-title">
        <div>
          <strong><Icon size={17} /> {title}</strong>
          <span>{subtitle}</span>
        </div>
      </div>
      <pre className="monitor-script"><code>{lines.join("\n")}</code></pre>
    </article>
  );
}

function PricingPage({ onBack }) {
  const plans = [
    {
      name: "Basic",
      eyebrow: "For public URL checks",
      price: "Free Plan",
      description: "Best for quick website posture checks and lightweight reporting.",
      cta: "Current Plan",
      tone: "basic",
      features: [
        "5 public URL scans",
        "Attack-surface discovery",
        "Security headers, TLS, cookies, CORS",
        "Exposed files and source maps",
        "Evidence-backed PDF reports",
      ],
    },
    {
      name: "Advanced",
      eyebrow: "For continuous visibility",
      price: "Monitoring",
      description: "Adds active monitoring and regression alerts for production websites.",
      cta: "Upgrade to Advanced",
      tone: "advanced",
      features: [
        "Everything in Basic",
        "50 public URL scans",
        "Active Monitoring module",
        "Header regression alerts",
        "SSL expiry monitoring",
        "Exposed asset drift detection",
        "New subdomain alerts",
      ],
    },
    {
      name: "Premium",
      eyebrow: "For code and release security",
      price: "Deep Security",
      description: "Adds source-code and repository scanning for deeper engineering workflows.",
      cta: "Upgrade to Premium",
      tone: "premium",
      features: [
        "Everything in Advanced",
        "Unlimited public URL scans",
        "Deep Scan module",
        "Source-code risk analysis",
        "Dependency CVE checks",
        "Secret and token detection",
        "CI/CD command-line scanning",
      ],
    },
  ];

  return (
    <main className="pricing-page">
      <header className="pricing-page-nav">
        <button className="secondary-action" type="button" onClick={onBack}>
          <ArrowUpRight size={17} /> Back to dashboard
        </button>
        <div className="pricing-page-brand">
          <span><Globe2 size={20} /></span>
          <strong>Security Tool</strong>
        </div>
        <button className="primary-action contact-sales-btn" type="button">
          <Mail size={17} /> Contact Sales
        </button>
      </header>

      <section className="pricing-page-content">
        <div className="pricing-page-heading">
          <p className="eyebrow">Plans & pricing</p>
          <h1>Choose the right security coverage</h1>
          <span>Start with public URL scanning, add continuous monitoring when production visibility matters, and unlock source-code Deep Scan for release security.</span>
        </div>

        <div className="pricing-grid">
          {plans.map((plan) => (
            <article className={`pricing-card ${plan.tone}`} key={plan.name}>
              <div className="pricing-card-head">
                <span>{plan.eyebrow}</span>
                <h2>{plan.name}</h2>
                <strong>{plan.price}</strong>
                <p>{plan.description}</p>
              </div>
              <button className={plan.name === "Basic" ? "secondary-action" : "primary-action"} type="button">
                {plan.cta}
              </button>
              <div className="pricing-features">
                {plan.features.map((feature) => (
                  <div key={feature}>
                    <CheckCircle2 size={17} />
                    <span>{feature}</span>
                  </div>
                ))}
              </div>
            </article>
          ))}
        </div>

        <section className="pricing-sales-panel">
          <div>
            <strong>Need higher limits or team rollout?</strong>
            <span>Talk to sales for custom scan volume, team access, security review workflows, and onboarding support.</span>
          </div>
          <button className="primary-action" type="button">
            <Mail size={17} /> Contact Sales
          </button>
        </section>
      </section>
    </main>
  );
}

function VulnerabilitiesPage() {
  const [findings, setFindings] = useState([]);
  const [totalFindings, setTotalFindings] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const pageSize = 20;
  const [filters, setFilters] = useState({
    search: "",
    severity: "all",
    status: "all",
    domain: "all",
    scanType: "all",
  });

  async function loadFindings() {
    setLoading(true);
    setError("");
    try {
      const params = new URLSearchParams({
        page: String(page),
        page_size: String(pageSize),
      });
      if (filters.search.trim()) params.set("search", filters.search.trim());
      if (filters.severity !== "all") params.set("severity", filters.severity);
      if (filters.status !== "all") params.set("status", filters.status);
      if (filters.domain !== "all") params.set("domain", filters.domain);
      if (filters.scanType !== "all") params.set("scan_type", filters.scanType);
      const response = await fetch(apiUrl(`/api/findings?${params.toString()}`));
      if (!response.ok) throw new Error("Findings request failed");
      const payload = await response.json();
      const items = Array.isArray(payload) ? payload : payload.items || [];
      setFindings(items);
      setTotalFindings(Array.isArray(payload) ? items.length : Number(payload.total || 0));
    } catch {
      setError("Could not load vulnerabilities. Confirm the backend is running and MongoDB is connected.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadFindings();
  }, [page, filters.search, filters.severity, filters.status, filters.domain, filters.scanType]);

  const domains = useMemo(() => {
    return Array.from(new Set(findings.map((finding) => finding.domain).filter(Boolean))).sort();
  }, [findings]);

  const summary = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach((finding) => {
      const severity = String(finding.severity || "info").toLowerCase();
      counts[severity in counts ? severity : "info"] += 1;
    });
    return {
      total: totalFindings,
      domains: domains.length,
      open: findings.filter((finding) => String(finding.status || "open").toLowerCase() === "open").length,
      counts,
    };
  }, [findings, domains, totalFindings]);

  const totalPages = Math.max(1, Math.ceil(totalFindings / pageSize));
  const pageStart = totalFindings ? (page - 1) * pageSize + 1 : 0;
  const pageEnd = Math.min(totalFindings, page * pageSize);

  function updateFilter(key, value) {
    setFilters((current) => ({ ...current, [key]: value }));
    setPage(1);
  }

  return (
    <section className="page">
      <div className="page-heading">
        <div>
          <p className="eyebrow">All findings</p>
          <h1>Vulnerabilities</h1>
        </div>
        <button className="secondary-action" type="button" onClick={loadFindings}>
          <RefreshCw size={17} /> Refresh
        </button>
      </div>

      <section className="hint-panel vulnerability-intro-panel">
        <AlertTriangle size={20} />
        <div>
          <strong>What this page is for</strong>
          <span>
            This view brings together vulnerabilities found by URL Scan and Deep Scan. Use it to filter by severity, status, domain, scan type, or scan ID, then open each row for evidence and remediation before marking the issue in your workflow.
          </span>
        </div>
      </section>

      <div className="vuln-summary-grid">
        <StatCard label="Total vulnerabilities" value={summary.total} detail="Matching current filters" icon={AlertTriangle} tone={summary.counts.critical || summary.counts.high ? "High" : "Info"} />
        <StatCard label="Domains on page" value={summary.domains} detail="Visible in current result page" icon={Globe2} />
        <StatCard label="Open on page" value={summary.open} detail="Current page only" icon={BarChart3} tone={summary.open ? "Medium" : "Info"} />
      </div>

      <section className="panel vulnerability-workbench">
        <div className="vulnerability-filters">
          <label className="filter-search">
            <Search size={17} />
            <input value={filters.search} onChange={(event) => updateFilter("search", event.target.value)} placeholder="Search vulnerability, domain, URL, scan ID..." />
          </label>
          <label>
            Severity
            <select value={filters.severity} onChange={(event) => updateFilter("severity", event.target.value)}>
              <option value="all">All severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
          </label>
          <label>
            Status
            <select value={filters.status} onChange={(event) => updateFilter("status", event.target.value)}>
              <option value="all">All statuses</option>
              <option value="open">Open</option>
              <option value="fixed">Fixed</option>
              <option value="false_positive">False positive</option>
              <option value="accepted_risk">Accepted risk</option>
            </select>
          </label>
          <label>
            Domain
            <select value={filters.domain} onChange={(event) => updateFilter("domain", event.target.value)}>
              <option value="all">All domains</option>
              {domains.map((domain) => (
                <option value={domain} key={domain}>{domain}</option>
              ))}
            </select>
          </label>
          <label>
            Scan type
            <select value={filters.scanType} onChange={(event) => updateFilter("scanType", event.target.value)}>
              <option value="all">All scan types</option>
              <option value="url_scan">URL Scan</option>
              <option value="deep_scan">Deep Scan</option>
            </select>
          </label>
        </div>

        <div className="severity-strip">
          {Object.entries(summary.counts).map(([severity, count]) => (
            <span className={severity} key={severity}>{severity}: <strong>{count}</strong></span>
          ))}
        </div>

        {error ? <div className="error-box">{error}</div> : null}

        <div className="vulnerability-table-wrap">
          <div className="vulnerability-table-head">
            <span>Severity</span>
            <span>Vulnerability</span>
            <span>Domain</span>
            <span>Status</span>
            <span>Scanned from</span>
            <span>Scan ID</span>
            <span>Detected</span>
          </div>
          {loading ? (
            <div className="vulnerability-empty">
              <Loader2 className="spin" size={20} />
              <span>Loading vulnerabilities...</span>
            </div>
          ) : findings.length ? (
            findings.map((finding, index) => (
              <VulnerabilityRow finding={finding} key={finding.id || `${finding.scan_id}-${index}`} />
            ))
          ) : (
            <div className="vulnerability-empty">
              <CheckCircle2 size={20} />
              <span>No vulnerabilities match the current filters.</span>
            </div>
          )}
        </div>
        <div className="vulnerability-pagination">
          <span>{pageStart}-{pageEnd} of {totalFindings} vulnerabilities</span>
          <div>
            <button className="secondary-action" type="button" disabled={page <= 1 || loading} onClick={() => setPage((value) => Math.max(1, value - 1))}>
              Previous
            </button>
            <strong>Page {page} of {totalPages}</strong>
            <button className="secondary-action" type="button" disabled={page >= totalPages || loading} onClick={() => setPage((value) => Math.min(totalPages, value + 1))}>
              Next
            </button>
          </div>
        </div>
      </section>
    </section>
  );
}

function VulnerabilityRow({ finding }) {
  const [open, setOpen] = useState(false);
  const severity = String(finding.severity || "info").toLowerCase();
  const status = String(finding.status || "open").replace(/_/g, " ");
  const source = finding.scanned_from || sourceLabel(finding);
  const detectedAt = finding.created_at ? formatDateTime(finding.created_at) : "Not available";

  return (
    <article className={`vulnerability-row-wrap ${severity}`}>
      <button className="vulnerability-row" type="button" onClick={() => setOpen((value) => !value)}>
        <span className="severity-badge">{severity}</span>
        <strong>{finding.vulnerability_name || "Security finding"}</strong>
        <span>{finding.domain || "Unknown domain"}</span>
        <span className="status-badge">{status}</span>
        <span>{source}</span>
        <code>{finding.scan_id || "No scan ID"}</code>
        <span>{detectedAt}</span>
      </button>
      {open ? (
        <div className="vulnerability-details">
          <div>
            <span>Description</span>
            <p>{finding.description || "No description was stored for this finding."}</p>
          </div>
          <div>
            <span>URL</span>
            <p>{finding.url || "Not available"}</p>
          </div>
          <div>
            <span>Remediation</span>
            <p>{finding.remediation || "Validate the finding and remediate according to your security standards."}</p>
          </div>
          <div>
            <span>Evidence</span>
            <code>{safeJson(finding.evidence || finding.raw || {})}</code>
          </div>
        </div>
      ) : null}
    </article>
  );
}

function sourceLabel(item) {
  return item?.scan_source === "deep_scan" ? "Deep Scan" : "URL Scan";
}

function safeJson(value) {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value || "Evidence not available");
  }
}

function ActiveMonitoring({ openPricing }) {
  const monitorScript = [
    '<script src="https://cdn.securitytool.app/monitor.js" async></script>',
    '<script>',
    '  SecurityToolMonitor.init({ siteId: "YOUR_SITE_ID" });',
    '</script>',
  ];

  return (
    <section className="page">
      <div className="page-heading">
        <div>
          <p className="eyebrow">Advanced module</p>
          <h1>Active Monitoring</h1>
        </div>
        <span className="locked-plan-pill">
          <Lock size={15} /> Advanced Plan
        </span>
      </div>

      <section className="locked-module">
        <div className="locked-hero">
          <div className="locked-icon">
            <Lock size={28} />
          </div>
          <div>
            <p className="eyebrow">Locked service</p>
            <h2>Upgrade to Advanced Plan to avail this service</h2>
            <span>
              Active Monitoring watches your public website between manual scans. It is designed for early warning when security posture changes, new exposed assets appear, or browser-facing risk signals are detected after deployment.
            </span>
          </div>
          <button className="primary-action" type="button" onClick={openPricing}>
            <Sparkles size={18} /> Upgrade to Advanced
          </button>
        </div>

        <section className="panel monitoring-guide module-guide-top">
          <div className="panel-title">
            <strong>How to add this in a header page</strong>
            <span>Recommended placement for reliable monitoring</span>
          </div>
          <div className="guide-steps">
            <div>
              <strong>1</strong>
              <span>Open the common layout file that renders your site header, usually `layout`, `app`, `_document`, or the shared HTML template.</span>
            </div>
            <div>
              <strong>2</strong>
              <span>Paste the script before the closing `&lt;/head&gt;` tag so it loads on every public page.</span>
            </div>
            <div>
              <strong>3</strong>
              <span>Replace `YOUR_SITE_ID` with the site ID generated inside Security Tool after domain verification.</span>
            </div>
            <div>
              <strong>4</strong>
              <span>Deploy your site, then run one manual scan to establish the first monitoring baseline.</span>
            </div>
          </div>
        </section>

        <div className="monitoring-grid">
          <article className="panel monitoring-panel">
            <div className="panel-title">
              <strong>What this module does</strong>
              <span>Continuous browser-side and public exposure monitoring</span>
            </div>
            <div className="monitoring-feature-list">
              <div>
                <CheckCircle2 size={18} />
                <span>Detects important client-side errors, broken security flows, and risky runtime behavior signals.</span>
              </div>
              <div>
                <CheckCircle2 size={18} />
                <span>Tracks suspicious frontend changes such as newly exposed scripts, source maps, API routes, and sensitive paths.</span>
              </div>
              <div>
                <CheckCircle2 size={18} />
                <span>Alerts when security headers, TLS posture, exposed assets, or public attack surface drift from the last known good state.</span>
              </div>
              <div>
                <CheckCircle2 size={18} />
                <span>Connects monitoring events with scan findings so teams can prioritize what changed after releases.</span>
              </div>
            </div>
          </article>

          <article className="panel monitoring-panel">
            <div className="panel-title">
              <strong>Install script</strong>
              <span>Add this to your website header after upgrading</span>
            </div>
            <pre className="monitor-script"><code>{monitorScript.join("\n")}</code></pre>
          </article>
        </div>

      </section>
    </section>
  );
}

function Topbar({ target, setTarget, account, openPricing }) {
  const planName = account?.account_plan?.name || "Basic";
  const scansLeft = Number.isFinite(Number(account?.scans_left)) ? Number(account.scans_left) : 5;
  return (
    <header className="topbar">
      <label className="search-field">
        <Search size={18} />
        <input value={target} onChange={(event) => setTarget(event.target.value)} placeholder="Search or scan your domain..." />
      </label>
      <div className="scan-quota-pill">
        <span>{Math.max(0, scansLeft)}</span>
        <strong>Scans Left</strong>
      </div>
      <div className="plan-pill">
        <div>
          <span>Current Plan</span>
          <strong>{planName}</strong>
        </div>
        <button type="button" onClick={openPricing}>Upgrade</button>
      </div>
    </header>
  );
}

function Dashboard({ totals, history, dashboardSummary, recentScans, onScan, openScan, account }) {
  const domains = dashboardSummary?.domains?.items || buildDomainOverview(history);
  const recentVulnerabilities = dashboardSummary?.recent_vulnerabilities || [];
  const firstName = account?.first_name || "User";

  return (
    <section className="page">
      <div className="page-heading">
        <div>
          <p className="eyebrow">Your security Portal</p>
          <h1>Welcome, {firstName}</h1>
        </div>
        <button className="primary-action" type="button" onClick={openScan}>
          <Radar size={18} /> Scan a new domain
        </button>
      </div>

      <div className="stat-grid">
        <StatCard label="Domains monitored" value={totals.domains} detail={`${totals.scans} scans stored`} icon={Globe2} />
        <StatCard label="All vulnerabilities" value={totals.vulnerabilities} detail={`${totals.byType?.url_scan || 0} URL / ${totals.byType?.deep_scan || 0} Deep scans`} icon={AlertTriangle} tone={totals.risk} />
        <StatCard label="Processing now" value={totals.processing || 0} detail={`${totals.failed || 0} failed scans stored`} icon={Activity} tone={totals.processing ? "Medium" : "Info"} />
        <StatCard label="Current top risk" value={totals.risk} detail="From Supabase vulnerabilities" icon={ShieldCheck} tone={totals.risk} />
      </div>

      <div className="dashboard-stack">
        <section className="panel">
          <div className="panel-title">
            <strong>Severity breakdown</strong>
            <span>Loaded from Supabase vulnerabilities</span>
          </div>
          <div className="severity-grid">
            {Object.entries(totals.counts).map(([severity, count]) => (
              <div className={`severity-card ${severityClass(severity)}`} key={severity}>
                <span>{severity}</span>
                <strong>{count}</strong>
              </div>
            ))}
          </div>
        </section>

        <section className="panel">
          <div className="panel-title">
            <strong>All domain overview</strong>
            <span>Built from stored URL and Deep Scan rows</span>
          </div>
          <DomainOverview domains={domains} onScan={onScan} />
        </section>

        <section className="panel">
          <div className="panel-title">
            <strong>Recent scans</strong>
            <span>Latest Supabase scan records</span>
          </div>
          <RecentScansList scans={recentScans || []} onScan={onScan} />
        </section>

        <section className="panel">
          <div className="panel-title">
            <strong>Recent vulnerabilities</strong>
            <span>Newest stored URL and Deep Scan findings</span>
          </div>
          <RecentVulnerabilitiesList vulnerabilities={recentVulnerabilities} />
        </section>
      </div>
    </section>
  );
}

function DomainOverview({ domains, onScan }) {
  if (!domains.length) {
    return (
      <div className="history-empty">
        <CheckCircle2 size={20} />
        <span>No domain overview yet. Run a scan to populate posture data.</span>
      </div>
    );
  }

  return (
    <div className="domain-overview">
      {domains.map((item) => (
        <article className={`domain-overview-row ${severityClass(item.risk)}`} key={item.domain}>
          <div className="domain-main">
            <strong>{item.domain}</strong>
            <span>
              {item.scans} scans - {item.total} findings - Latest {item.latest}
            </span>
          </div>
          <div className="posture-bar" aria-label={`${item.protection}% protected`}>
            <div style={{ width: `${item.protection}%` }} />
          </div>
          <div className="domain-guidance">
            <em>{item.protection}% protected</em>
            <span>{item.guidance}</span>
          </div>
          <button type="button" onClick={() => onScan(item.target)}>
            <RefreshCw size={16} />
          </button>
        </article>
      ))}
    </div>
  );
}

function RecentVulnerabilitiesList({ vulnerabilities }) {
  if (!vulnerabilities?.length) {
    return (
      <div className="history-empty">
        <CheckCircle2 size={20} />
        <span>No vulnerabilities stored yet.</span>
      </div>
    );
  }

  return (
    <div className="recent-vulnerability-list">
      {vulnerabilities.slice(0, 8).map((finding, index) => {
        const severity = String(finding.severity || "info").toLowerCase();
        return (
          <article className={`recent-vulnerability-row ${severity}`} key={finding.id || `${finding.scan_id}-${index}`}>
            <span className="severity-badge">{severity}</span>
            <div>
              <strong>{finding.vulnerability_name || "Security finding"}</strong>
              <small>{finding.scanned_from || sourceLabel(finding)} - {finding.domain || "Unknown domain"} - {formatDateTime(finding.created_at)}</small>
            </div>
          </article>
        );
      })}
    </div>
  );
}

function StatCard({ label, value, detail, icon: Icon, tone = "Info" }) {
  return (
    <article className={`stat-card ${severityClass(tone)}`}>
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
        <small>{detail}</small>
      </div>
      <Icon size={20} />
    </article>
  );
}

function ScanView(props) {
  const {
    target,
    setTarget,
    startScan,
    isScanning,
    liveStatus,
    report,
    error,
    downloadPdf,
    scanId,
    recentScans,
    onScan,
  } = props;

  return (
    <section className="page">
      <div className="page-heading">
        <div>
          <p className="eyebrow">Website security scan</p>
          <h1>Run a website security scan</h1>
        </div>
      </div>

      <section className="hint-panel scan-checks-panel">
        <Target size={20} />
        <div>
          <strong>What this scan checks</strong>
          <span>Maps public pages, forms, inputs, cookies, and API calls, then reviews headers, TLS, CORS, exposed paths, source maps, frontend secrets, risky methods, and low-risk validation signals.</span>
        </div>
      </section>

      <div className="scan-layout scan-layout-single">
        <div className="main-column">
          <form className="scan-card" onSubmit={startScan}>
            <label>
              Website domain
              <div className="domain-row">
                <Globe2 size={18} />
                <input value={target} onChange={(event) => setTarget(event.target.value)} placeholder="example.com" required />
                <button className="primary-action" type="submit" disabled={isScanning}>
                  {isScanning ? <Loader2 className="spin" size={18} /> : <ArrowUpRight size={18} />}
                  Run scan
                </button>
              </div>
            </label>
          </form>
        </div>
      </div>

      <section className="panel recent-scans-panel">
        <div className="panel-title">
          <strong>Recent scans</strong>
          <span>Loaded from Supabase scan history</span>
        </div>
        <RecentScansList scans={recentScans} onScan={onScan} />
      </section>

      {error ? <div className="error-box full-width-panel">{error}</div> : null}
      {liveStatus ? <LiveStatus liveStatus={liveStatus} /> : null}
      {report ? <ReportSummary report={report} scanId={scanId} downloadPdf={downloadPdf} /> : null}
    </section>
  );
}

function LiveStatus({ liveStatus }) {
  if (!liveStatus) {
    return (
      <section className="empty-state">
        <ShieldCheck size={42} />
        <strong>No scan yet</strong>
        <span>Enter a domain above to see live scanner progress.</span>
      </section>
    );
  }

  const metrics = liveStatus.live_metrics || {};
  const progress = liveStatus.progress || {};
  const timing = liveStatus.timing || {};
  const recent = liveStatus.events_log?.recent || [];
  const status = cleanStatus(liveStatus.status);
  const isCompleted = status.toLowerCase() === "completed" || liveStatus.current_step === "Scan complete";
  const elapsedSeconds = timing.elapsed_seconds ?? timing.elapsedSeconds;
  const etaLabel = isCompleted ? "Completed in" : "ETA";
  const etaValue = isCompleted
    ? formatDuration(elapsedSeconds)
    : timing.estimated_remaining_seconds == null
      ? "Calculating ETA"
      : `${formatDuration(timing.estimated_remaining_seconds)} remaining`;

  return (
    <section className="live-panel">
      <div className="panel-title horizontal">
        <div>
          <strong>{liveStatus.current_step || "Preparing scan"}</strong>
          <span>{status}</span>
        </div>
        <Activity size={20} />
      </div>
      <div className="progress-track">
        <div style={{ width: `${Math.max(4, Math.min(100, Number(progress.percent) || 8))}%` }} />
      </div>
      <div className="metrics-table" role="table" aria-label="Scan metrics">
        <div className="metrics-row metrics-head" role="row">
          <span role="columnheader">Pages</span>
          <span role="columnheader">Forms</span>
          <span role="columnheader">Inputs</span>
          <span role="columnheader">API calls</span>
          <span role="columnheader">Findings</span>
          <span role="columnheader">{etaLabel}</span>
        </div>
        <div className="metrics-row" role="row">
          <strong role="cell">{metrics.pages_crawled || 0}</strong>
          <strong role="cell">{metrics.forms_found || 0}</strong>
          <strong role="cell">{metrics.inputs_discovered || 0}</strong>
          <strong role="cell">{metrics.api_calls_captured || 0}</strong>
          <strong role="cell">{metrics.findings_so_far || 0}</strong>
          <strong role="cell" className="eta-cell">{etaValue}</strong>
        </div>
      </div>
      <div className="event-feed">
        {recent.length ? (
          recent.slice(-6).map((event, index) => (
            <div className="event-row" key={`${event.time}-${index}`}>
              <Clock3 size={16} />
              <span>{String(event.message || "Scanner activity").replace(/^[^A-Za-z]*/, "")}</span>
            </div>
          ))
        ) : (
          <div className="event-row">
            <Clock3 size={16} />
            <span>Waiting for scanner events.</span>
          </div>
        )}
      </div>
    </section>
  );
}

function ReportSummary({ report, downloadPdf }) {
  const [openFinding, setOpenFinding] = useState(null);
  const meta = report.scan_metadata || {};
  const summary = report.executive_summary || {};
  const completedIn = meta.elapsed_seconds == null ? "" : `Completed in ${formatDuration(meta.elapsed_seconds)}.`;
  const counts = getFindingCounts(report);
  const score = scoreFromCounts(counts);
  const items = [...(report.assessment_items || [])].sort((a, b) => {
    const aRank = severityOrder[a.severity] ?? severityOrder.Info;
    const bRank = severityOrder[b.severity] ?? severityOrder.Info;
    return aRank - bRank;
  });

  return (
    <section className="report-panel">
      <div className="report-overview">
        <div className="report-head">
          <div>
            <p className="eyebrow">Scan complete</p>
            <h2>{domainFromUrl(meta.target || "Security report")}</h2>
            {completedIn ? <strong className="completion-time">{completedIn}</strong> : null}
            <span>{summary.summary || "Review detected issues and supporting evidence."}</span>
          </div>
          <button className="secondary-action" type="button" onClick={downloadPdf}>
            <Download size={18} /> PDF
          </button>
        </div>

        <SeverityGauge score={score} risk={summary.risk_rating || riskFromCounts(counts)} />
      </div>

      <div className="findings-table">
        <div className="findings-table-head">
          <span>Finding</span>
          <span>Status</span>
          <span>Severity</span>
        </div>
        {items.length ? (
          items.slice(0, 10).map((item, index) => {
            const isOpen = openFinding === index;
            return (
              <div className={`finding-row-wrap ${severityClass(item.severity)}`} key={`${item.title}-${index}`}>
                <button className="finding-row" type="button" onClick={() => setOpenFinding(isOpen ? null : index)}>
                  <span className="finding-title-cell">
                    {isOpen ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                    <strong>{item.title || "Security finding"}</strong>
                  </span>
                  <span>{item.status || "Review required"}</span>
                  <em>{item.severity || "Info"}</em>
                </button>
                {isOpen ? <FindingDetails item={item} /> : null}
              </div>
            );
          })
        ) : (
          <div className="finding-row-wrap info">
            <div className="finding-row static">
              <span className="finding-title-cell">
                <CheckCircle2 size={16} />
                <strong>No actionable findings returned</strong>
              </span>
              <span>The scanner completed without assessment items.</span>
              <em>Info</em>
            </div>
          </div>
        )}
      </div>
    </section>
  );
}

function SeverityGauge({ score, risk }) {
  const rotation = -90 + score * 18;
  return (
    <aside className={`severity-gauge ${severityClass(risk)}`}>
      <div className="gauge-arc">
        <div className="gauge-needle" style={{ transform: `rotate(${rotation}deg)` }} />
        <div className="gauge-center" />
      </div>
      <div className="gauge-copy">
        <span>Severity rating</span>
        <strong>{score}/10</strong>
        <em>{risk}</em>
      </div>
    </aside>
  );
}

function FindingDetails({ item }) {
  return (
    <div className="finding-details">
      <div>
        <span>Status</span>
        <p>{item.status || "Review required"}</p>
      </div>
      <div>
        <span>Analysis</span>
        <p>{item.analysis || "Review this issue in application context."}</p>
      </div>
      <div>
        <span>Evidence</span>
        <code>{item.evidence || "Evidence not available"}</code>
      </div>
      <div>
        <span>Recommended action</span>
        <p>{item.fix || "Validate and remediate according to security standards."}</p>
      </div>
    </div>
  );
}

function HistoryList({ history, onScan, compact = false }) {
  if (!history.length) {
    return (
      <div className="history-empty">
        <CheckCircle2 size={20} />
        <span>No completed scans saved yet.</span>
      </div>
    );
  }

  return (
    <div className={compact ? "history-list compact" : "history-list"}>
      {history.slice(0, compact ? 5 : 8).map((item) => (
        <div className="history-row" key={item.id}>
          <div>
            <strong>{item.domain}</strong>
            <span>
              {item.total} findings - {item.scannedAt}
            </span>
          </div>
          <button type="button" onClick={() => onScan(item.target)} title="Re-scan domain">
            <RefreshCw size={16} />
          </button>
        </div>
      ))}
    </div>
  );
}

function RecentScansList({ scans, onScan }) {
  if (scans?.length) {
    return (
      <div className="recent-scan-list">
        {scans.slice(0, 6).map((scan) => {
          const url = scan.url || scan.target || "";
          const domain = scan.domain || domainFromUrl(url || "Unknown domain");
          const status = String(scan.status || "unknown");
          const source = scan.scanned_from || sourceLabel(scan);
          const findings = scan.summary?.findings ?? scan.findings_found ?? 0;
          const createdAt = scan.created_at ? formatDateTime(scan.created_at) : "No timestamp";
          return (
            <article className="recent-scan-row" key={scan.scan_id || `${domain}-${createdAt}`}>
              <div>
                <strong>{domain}</strong>
                <span>{source} - {status} - {findings} findings</span>
                <small>{createdAt}</small>
              </div>
              <button type="button" onClick={() => onScan(url || domain)} title="Re-scan domain">
                <RefreshCw size={16} />
              </button>
            </article>
          );
        })}
      </div>
    );
  }

  return (
    <div className="history-empty">
      <strong>No recent scans stored yet.</strong>
      <span>Run a scan after MongoDB is connected and it will appear here.</span>
    </div>
  );
}

export default App;

