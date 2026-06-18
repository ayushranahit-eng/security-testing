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
  const [recentScans, setRecentScans] = useState([]);
  const [account, setAccount] = useState(defaultAccount);
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
    loadAccount();
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
          <Dashboard totals={totals} history={history} onScan={(value) => startScan(null, value)} openScan={() => setActiveView("scan")} account={account} />
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

function DeepScan({ openPricing }) {
  const linuxCommand = [
    "ssh deploy@your-linux-server",
    "cd /var/www/your-app",
    'curl -fsSL https://cdn.securitytool.app/deep-scan.sh | bash -s -- \\',
    '  --repo . --site-id YOUR_SITE_ID --branch main',
  ];
  const gitBashCommand = [
    "cd /c/projects/your-app",
    'export SECURITY_TOOL_TOKEN="YOUR_TOKEN"',
    "npx @securitytool/deep-scan --repo . \\",
    "  --site-id YOUR_SITE_ID --branch main",
  ];
  const ciCommand = [
    "securitytool deep-scan --repo .",
    "securitytool deep-scan --lockfiles package-lock.json requirements.txt",
    "securitytool deep-scan --diff-only origin/main",
    "securitytool deep-scan --report json",
  ];

  return (
    <section className="page">
      <div className="page-heading">
        <div>
          <p className="eyebrow">Premium module</p>
          <h1>Deep Scan</h1>
        </div>
        <span className="locked-plan-pill premium">
          <Lock size={15} /> Premium Plan
        </span>
      </div>

      <section className="locked-module">
        <div className="locked-hero">
          <div className="locked-icon">
            <Code2 size={28} />
          </div>
          <div>
            <p className="eyebrow">Locked service</p>
            <h2>Upgrade to Premium Plan to run source-code deep scans</h2>
            <span>
              Deep Scan connects to your repository or server checkout and reviews source code, dependency files, configuration, secrets, and deployment artifacts. It complements public URL scanning by finding issues that are not visible from the outside.
            </span>
          </div>
          <button className="primary-action" type="button" onClick={openPricing}>
            <Sparkles size={18} /> Upgrade to Premium
          </button>
        </div>

        <div className="monitoring-grid deep-scan-grid">
          <article className="panel monitoring-panel">
            <div className="panel-title">
              <strong>What Deep Scan checks</strong>
              <span>Repository-level analysis before code reaches production</span>
            </div>
            <div className="monitoring-feature-list">
              <div>
                <CheckCircle2 size={18} />
                <span>Hardcoded secrets, API keys, tokens, private keys, `.env` files, and risky credentials committed in source.</span>
              </div>
              <div>
                <CheckCircle2 size={18} />
                <span>Dependency CVEs from npm, Python, and lockfiles, including vulnerable versions and upgrade guidance.</span>
              </div>
              <div>
                <CheckCircle2 size={18} />
                <span>Security-sensitive code patterns such as SQL injection risks, unsafe HTML rendering, command execution, SSRF sinks, and weak auth logic.</span>
              </div>
              <div>
                <CheckCircle2 size={18} />
                <span>Infrastructure and deployment mistakes such as exposed Docker files, permissive CORS config, debug flags, weak headers, and public cloud/IaC risk signals.</span>
              </div>
            </div>
          </article>

          <article className="panel monitoring-panel">
            <div className="panel-title">
              <strong>Possible vulnerability output</strong>
              <span>Examples of what the report can classify</span>
            </div>
            <div className="deep-vuln-list">
              <span className="critical">Critical - Private key committed in repository</span>
              <span className="high">High - SQL query built with string concatenation</span>
              <span className="high">High - Vulnerable npm dependency with known CVE</span>
              <span className="medium">Medium - JWT token missing expiry validation</span>
              <span className="medium">Medium - Debug mode enabled in production config</span>
              <span className="low">Low - Server version exposed in deployment config</span>
            </div>
          </article>
        </div>

        <div className="command-grid">
          <CommandCard icon={Server} title="Linux server over SSH" subtitle="Run from the checked-out production or staging repository" lines={linuxCommand} />
          <CommandCard icon={Terminal} title="Git Bash / local repository" subtitle="Run inside your project folder on Windows Git Bash" lines={gitBashCommand} />
          <CommandCard icon={Code2} title="CI or scripted usage" subtitle="Useful for GitHub Actions, GitLab CI, or release pipelines" lines={ciCommand} />
        </div>

        <section className="panel monitoring-guide">
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
      </section>
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
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [filters, setFilters] = useState({
    search: "",
    severity: "all",
    status: "all",
    domain: "all",
  });

  async function loadFindings() {
    setLoading(true);
    setError("");
    try {
      const response = await fetch(apiUrl("/api/findings?limit=200"));
      if (!response.ok) throw new Error("Findings request failed");
      const payload = await response.json();
      setFindings(Array.isArray(payload) ? payload : []);
    } catch {
      setError("Could not load vulnerabilities. Confirm the backend is running and MongoDB is connected.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadFindings();
  }, []);

  const domains = useMemo(() => {
    return Array.from(new Set(findings.map((finding) => finding.domain).filter(Boolean))).sort();
  }, [findings]);

  const filteredFindings = useMemo(() => {
    const search = filters.search.trim().toLowerCase();
    return findings
      .filter((finding) => {
        const severity = String(finding.severity || "info").toLowerCase();
        const status = String(finding.status || "open").toLowerCase();
        const domain = String(finding.domain || "");
        const haystack = [
          finding.vulnerability_name,
          finding.description,
          finding.domain,
          finding.url,
          finding.scan_id,
        ].join(" ").toLowerCase();

        return (
          (filters.severity === "all" || severity === filters.severity) &&
          (filters.status === "all" || status === filters.status) &&
          (filters.domain === "all" || domain === filters.domain) &&
          (!search || haystack.includes(search))
        );
      })
      .sort((a, b) => {
        const aRank = severityOrder[String(a.severity || "Info").replace(/^\w/, (letter) => letter.toUpperCase())] ?? 4;
        const bRank = severityOrder[String(b.severity || "Info").replace(/^\w/, (letter) => letter.toUpperCase())] ?? 4;
        return aRank - bRank || String(b.created_at || "").localeCompare(String(a.created_at || ""));
      });
  }, [findings, filters]);

  const summary = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach((finding) => {
      const severity = String(finding.severity || "info").toLowerCase();
      counts[severity in counts ? severity : "info"] += 1;
    });
    return {
      total: findings.length,
      domains: domains.length,
      open: findings.filter((finding) => String(finding.status || "open").toLowerCase() === "open").length,
      counts,
    };
  }, [findings, domains]);

  function updateFilter(key, value) {
    setFilters((current) => ({ ...current, [key]: value }));
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

      <div className="vuln-summary-grid">
        <StatCard label="Total vulnerabilities" value={summary.total} detail="Across all stored scans" icon={AlertTriangle} tone={summary.counts.critical || summary.counts.high ? "High" : "Info"} />
        <StatCard label="Affected domains" value={summary.domains} detail="Domains with saved findings" icon={Globe2} />
        <StatCard label="Open findings" value={summary.open} detail="Not marked fixed or accepted" icon={BarChart3} tone={summary.open ? "Medium" : "Info"} />
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
            <span>Scan ID</span>
            <span>Detected</span>
          </div>
          {loading ? (
            <div className="vulnerability-empty">
              <Loader2 className="spin" size={20} />
              <span>Loading vulnerabilities...</span>
            </div>
          ) : filteredFindings.length ? (
            filteredFindings.map((finding, index) => (
              <VulnerabilityRow finding={finding} key={finding.id || `${finding.scan_id}-${index}`} />
            ))
          ) : (
            <div className="vulnerability-empty">
              <CheckCircle2 size={20} />
              <span>No vulnerabilities match the current filters.</span>
            </div>
          )}
        </div>
      </section>
    </section>
  );
}

function VulnerabilityRow({ finding }) {
  const [open, setOpen] = useState(false);
  const severity = String(finding.severity || "info").toLowerCase();
  const status = String(finding.status || "open").replace(/_/g, " ");
  const detectedAt = finding.created_at ? new Date(finding.created_at).toLocaleString() : "Not available";

  return (
    <article className={`vulnerability-row-wrap ${severity}`}>
      <button className="vulnerability-row" type="button" onClick={() => setOpen((value) => !value)}>
        <span className="severity-badge">{severity}</span>
        <strong>{finding.vulnerability_name || "Security finding"}</strong>
        <span>{finding.domain || "Unknown domain"}</span>
        <span className="status-badge">{status}</span>
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

        <section className="panel monitoring-guide">
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

function Dashboard({ totals, history, onScan, openScan, account }) {
  const domains = buildDomainOverview(history);
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
          <span>Loaded from MongoDB scan history</span>
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
          const findings = scan.summary?.findings ?? scan.findings_found ?? 0;
          const createdAt = scan.created_at ? new Date(scan.created_at).toLocaleString() : "No timestamp";
          return (
            <article className="recent-scan-row" key={scan.scan_id || `${domain}-${createdAt}`}>
              <div>
                <strong>{domain}</strong>
                <span>{status} - {findings} findings</span>
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

