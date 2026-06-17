import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  BarChart3,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock3,
  Download,
  Globe2,
  LayoutDashboard,
  LockKeyhole,
  Loader2,
  Palette,
  Radar,
  RefreshCw,
  Search,
  Settings2,
  ShieldCheck,
  Sparkles,
  Target,
  UserRound,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

const STORAGE_KEY = "hit-securescan-history-v1";
const emptyCounts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
const severityOrder = { Critical: 0, High: 1, Medium: 2, Low: 3, Informational: 4, Info: 4 };

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
    scannedAt: meta.scan_completed_at || new Date().toLocaleString(),
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
  const [target, setTarget] = useState("");
  const [scanId, setScanId] = useState("");
  const [liveStatus, setLiveStatus] = useState(null);
  const [report, setReport] = useState(null);
  const [error, setError] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const pollRef = useRef(null);

  const totals = useMemo(() => {
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
  }, [history]);

  useEffect(() => {
    return () => {
      if (pollRef.current) window.clearInterval(pollRef.current);
    };
  }, []);

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
      const response = await fetch("/api/scan", {
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
      pollRef.current = window.setInterval(() => pollScan(job.scan_id), 1800);
      await pollScan(job.scan_id);
    } catch (scanError) {
      setIsScanning(false);
      setError("Could not start the scan. Confirm the backend is running on http://localhost:8000.");
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
      const response = await fetch(`/api/scan/status/${id}?readable=true`);
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
        }));
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
    const response = await fetch(`/api/scan/status/${scanId}?pdf=true`);
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

  return (
    <div className="app-shell">
      <Sidebar activeView={activeView} setActiveView={setActiveView} totals={totals} />
      <main className="workspace">
        <Topbar target={target} setTarget={setTarget} />
        {activeView === "dashboard" ? (
          <Dashboard totals={totals} history={history} onScan={(value) => startScan(null, value)} openScan={() => setActiveView("scan")} />
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
            onScan={(value) => startScan(null, value)}
          />
        )}
      </main>
    </div>
  );
}

function Sidebar({ activeView, setActiveView }) {
  const [accountOpen, setAccountOpen] = useState(false);

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
        <button type="button">
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
            <strong>Ayush Rana</strong>
            <span>Basic Plan</span>
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
            <button className="advanced-upgrade" type="button">
              <Sparkles size={16} />
              <span>Upgrade to Advanced</span>
            </button>
          </div>
        ) : null}
      </div>
    </aside>
  );
}

function Topbar({ target, setTarget }) {
  return (
    <header className="topbar">
      <label className="search-field">
        <Search size={18} />
        <input value={target} onChange={(event) => setTarget(event.target.value)} placeholder="Search or scan your domain..." />
      </label>
      <div className="scan-quota-pill">
        <span>5</span>
        <strong>Free Scans Left</strong>
      </div>
      <div className="plan-pill">
        <div>
          <span>Current Plan</span>
          <strong>Basic</strong>
        </div>
        <button type="button">Upgrade</button>
      </div>
    </header>
  );
}

function Dashboard({ totals, history, onScan, openScan }) {
  const domains = buildDomainOverview(history);

  return (
    <section className="page">
      <div className="page-heading">
        <div>
          <p className="eyebrow">Your security Portal</p>
          <h1>Dashboard</h1>
        </div>
        <button className="primary-action" type="button" onClick={openScan}>
          <Radar size={18} /> Scan a new domain
        </button>
      </div>

      <div className="stat-grid">
        <StatCard label="Domains monitored" value={totals.domains} detail={`${totals.scans} scans stored`} icon={Globe2} />
        <StatCard label="All-time vulnerabilities" value={totals.vulnerabilities} detail="Across completed scans" icon={AlertTriangle} tone={totals.risk} />
        <StatCard label="Current top risk" value={totals.risk} detail="Based on saved history" icon={ShieldCheck} tone={totals.risk} />
      </div>

      <div className="dashboard-stack">
        <section className="panel">
          <div className="panel-title">
            <strong>Severity breakdown</strong>
            <span>Saved completed scan history</span>
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
            <span>Risk, protection score, and practical next step</span>
          </div>
          <DomainOverview domains={domains} onScan={onScan} />
        </section>

        <section className="panel">
          <div className="panel-title">
            <strong>Recent domains</strong>
            <span>Latest saved scans</span>
          </div>
          <HistoryList history={history} onScan={onScan} />
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
    history,
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

      <div className="scan-layout">
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

        <aside className="side-column">
          <section className="panel domain-panel">
            <div className="panel-title">
              <strong>Your domains</strong>
              <span>Saved from previous scans</span>
            </div>
            <HistoryList history={history} onScan={onScan} compact />
          </section>
        </aside>
      </div>

      {error ? <div className="error-box full-width-panel">{error}</div> : null}
      <LiveStatus liveStatus={liveStatus} />
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
          <span role="columnheader">ETA</span>
        </div>
        <div className="metrics-row" role="row">
          <strong role="cell">{metrics.pages_crawled || 0}</strong>
          <strong role="cell">{metrics.forms_found || 0}</strong>
          <strong role="cell">{metrics.inputs_discovered || 0}</strong>
          <strong role="cell">{metrics.api_calls_captured || 0}</strong>
          <strong role="cell">{metrics.findings_so_far || 0}</strong>
          <strong role="cell">{timing.estimated_remaining_seconds == null ? "..." : formatDuration(timing.estimated_remaining_seconds)}</strong>
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

export default App;
