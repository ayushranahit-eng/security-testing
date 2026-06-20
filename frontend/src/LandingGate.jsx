import {
  Activity,
  ArrowRight,
  BarChart3,
  CheckCircle2,
  Code2,
  Eye,
  EyeOff,
  FileText,
  Globe2,
  LockKeyhole,
  Mail,
  Menu,
  Radar,
  Search,
  ShieldCheck,
  Terminal,
  UserRound,
  X,
  Zap,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { apiUrl, authHeaders, clearStoredAuth, getStoredAuth, storeAuth } from "./api.js";
import DashboardApp from "./App.jsx";
import shieldLogo from "./assets/shield.png";

const navItems = ["Features", "How It Works", "Reports", "Pricing"];

const features = [
  {
    icon: Radar,
    title: "URL Attack Surface Scan",
    desc: "Crawls every public page, form, and API endpoint. Checks headers, cookies, TLS, CORS, exposed paths, and JS secrets.",
  },
  {
    icon: Terminal,
    title: "Deep Source-Code Scan",
    desc: "Runs inside the client repository. Finds hardcoded secrets, vulnerable dependencies, IaC mistakes, and CI/CD leaks.",
  },
  {
    icon: Activity,
    title: "Live Scan Progress",
    desc: "Watch the scanner in real time - pages crawled, forms tested, API calls captured, and findings as they arrive.",
  },
  {
    icon: BarChart3,
    title: "Vulnerability Dashboard",
    desc: "All findings in one place. Filter by severity, domain, scan type, or status. Track your security posture over time.",
  },
  {
    icon: FileText,
    title: "PDF & JSON Reports",
    desc: "Download engineer-ready reports with evidence, remediation steps, and executive summaries - in PDF or JSON.",
  },
  {
    icon: Code2,
    title: "SAST & IaC Analysis",
    desc: "Static analysis for SQL injection, command injection, deserialization, Docker, Kubernetes, Terraform, and GitHub Actions.",
  },
];

const steps = [
  {
    step: "01",
    title: "Enter your domain",
    desc: "Paste the target URL. Our scanner maps every reachable page, form, and API endpoint automatically.",
  },
  {
    step: "02",
    title: "Scanner runs in the background",
    desc: "Watch live progress while the engine checks headers, cookies, TLS, CORS, exposed paths, and JS secrets. Scan time depends on the number of pages and links in the target.",
  },
  {
    step: "03",
    title: "Review findings",
    desc: "Every finding includes severity, evidence, and a clear remediation step. Export as PDF or JSON.",
  },
  {
    step: "04",
    title: "Deep scan your source code",
    desc: "Run one command on the server to scan secrets, dependencies, IaC, and CI/CD files from inside the repo.",
  },
];

const checks = [
  "Security Headers", "TLS / SSL Certificate", "Cookie Flags", "CORS Policy",
  "Sensitive Path Exposure", "JavaScript Secrets", "Source Maps", "CSRF Risk",
  "GraphQL Introspection", "HTTP Methods", "Error Disclosure", "Directory Listing",
  "Hardcoded Secrets", "Vulnerable Dependencies", "Docker & Kubernetes", "Terraform IaC",
  "CI/CD Secrets", "Git History Leaks", "Auth & JWT Mistakes", "SAST Code Patterns",
];

const plans = [
  {
    name: "Basic",
    eyebrow: "For public URL checks",
    badge: "Free Plan",
    description: "Best for quick website posture checks and lightweight reporting.",
    features: [
      "5 public URL scans",
      "Attack-surface discovery",
      "Security headers, TLS, cookies, CORS",
      "Exposed files and source maps",
      "Evidence-backed PDF reports",
    ],
    cta: "Get Started Free",
    highlight: false,
  },
  {
    name: "Advanced",
    eyebrow: "For continuous visibility",
    badge: "Monitoring",
    description: "Adds active monitoring and regression alerts for production websites.",
    features: [
      "Everything in Basic",
      "50 public URL scans",
      "Active Monitoring module",
      "Header regression alerts",
      "SSL expiry monitoring",
      "Exposed asset drift detection",
      "New subdomain alerts",
    ],
    cta: "Contact Sales",
    highlight: true,
  },
  {
    name: "Premium",
    eyebrow: "For code and release security",
    badge: "Deep Security",
    description: "Adds source-code and repository scanning for deeper engineering workflows.",
    features: [
      "Everything in Advanced",
      "Unlimited public URL scans",
      "Deep Scan module",
      "Source-code risk analysis",
      "Dependency CVE checks",
      "Secret and token detection",
      "CI/CD command-line scanning",
    ],
    cta: "Contact Sales",
    highlight: false,
  },
];

function LandingGate() {
  const [menuOpen, setMenuOpen] = useState(false);
  const [showDashboard, setShowDashboard] = useState(false);
  const [loading, setLoading] = useState(false);
  const [bootstrapping, setBootstrapping] = useState(Boolean(getStoredAuth()));
  const [error, setError] = useState("");
  const [signupPrompt, setSignupPrompt] = useState("");

  useEffect(() => {
    if (getStoredAuth()) verifySession();
  }, []);

  async function verifySession() {
    setLoading(true);
    setError("");
    try {
      const response = await fetch(apiUrl("/api/me"), { headers: authHeaders() });
      if (!response.ok) throw new Error("Account verification failed");
      await response.json();
      setShowDashboard(true);
    } catch {
      clearStoredAuth();
      setError("Could not verify your session. Please sign in again.");
    } finally {
      setBootstrapping(false);
      setLoading(false);
    }
  }

  async function authenticate(mode, values) {
    setLoading(true);
    setError("");
    try {
      const response = await fetch(apiUrl(mode === "signup" ? "/api/auth/signup" : "/api/auth/signin"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(values),
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload.detail || "Authentication failed");
      storeAuth(payload);
      setSignupPrompt("");
      setShowDashboard(true);
    } catch (authError) {
      setError(authError.message || "Could not sign in. Confirm the backend is running.");
    } finally {
      setLoading(false);
    }
  }

  function promptCreateAccount(message = "Create an account to start your first scan and save the results in your dashboard.") {
    setSignupPrompt(message);
    document.getElementById("account-access")?.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  function handleLogout() {
    clearStoredAuth();
    setShowDashboard(false);
    setSignupPrompt("");
    setError("");
    setBootstrapping(false);
  }

  if (showDashboard) return <DashboardApp onLogout={handleLogout} />;
  if (bootstrapping) return null;

  return (
    <main className="landing-shell">

      {/* ── Nav ── */}
      <header className="landing-nav-wrap">
        <nav className="landing-nav">
          <a className="landing-logo" href="/">
            <span><img src={shieldLogo} alt="" /></span>
            <strong>Security Tool</strong>
          </a>
          <div className="landing-nav-links">
            {navItems.map((item) => (
              <a href={`#${item.toLowerCase().replace(/\s+/g, "-")}`} key={item}>{item}</a>
            ))}
          </div>
          <div className="landing-nav-actions">
            <button type="button" onClick={() => document.getElementById("account-access")?.scrollIntoView({ behavior: "smooth", block: "center" })} disabled={loading}>
              Sign in
            </button>
            <button className="landing-teal-btn" type="button" onClick={() => promptCreateAccount()} disabled={loading}>
              Start Free Scan <ArrowRight size={15} />
            </button>
          </div>
          <button className="landing-menu-btn" type="button" onClick={() => setMenuOpen((v) => !v)} aria-label="Toggle menu">
            {menuOpen ? <X size={20} /> : <Menu size={20} />}
          </button>
        </nav>
        {menuOpen ? (
          <div className="landing-mobile-menu">
            {navItems.map((item) => (
              <a href={`#${item.toLowerCase().replace(/\s+/g, "-")}`} key={item} onClick={() => setMenuOpen(false)}>{item}</a>
            ))}
            <button type="button" onClick={() => { setMenuOpen(false); document.getElementById("account-access")?.scrollIntoView({ behavior: "smooth", block: "center" }); }}>Sign in</button>
            <button type="button" onClick={() => { setMenuOpen(false); promptCreateAccount(); }}>Start Free Scan</button>
          </div>
        ) : null}
      </header>

      {/* ── Hero ── */}
      <section className="landing-hero" id="features">
        <NetworkMeshBackground variant="light" density="medium" />
        <div className="landing-hero-copy">
          <p className="landing-pill">
            <ShieldCheck size={14} /> Automated security assessment platform
          </p>
          <h1>
            <span>Find Security Risks</span>
            <span className="landing-h1-accent">Before Attackers Do</span>
          </h1>
          <p className="landing-subtitle">
            Automated attack-surface discovery, exposure detection, vulnerability validation, and evidence-backed reporting - for web apps and source code.
          </p>

          <form
            className="landing-url-bar"
            onSubmit={(e) => { e.preventDefault(); promptCreateAccount("Create an account to run a scan for this domain and keep the findings in your workspace."); }}
          >
            <Globe2 size={21} />
            <input placeholder="https://your-company.com" type="url" aria-label="Website URL" />
            <button type="submit" disabled={loading}>
              Scan now <ArrowRight size={17} />
            </button>
          </form>

          {signupPrompt ? (
            <div className="landing-inline-notice landing-scan-notice" role="status">
              <strong>Create an account to continue</strong>
              <span>{signupPrompt}</span>
              <button type="button" onClick={() => setSignupPrompt("")}>Dismiss</button>
            </div>
          ) : null}

          <div className="landing-trust-row">
            {["URL Scan", "Deep Scan", "PDF Reports", "Live Progress"].map((item) => (
              <span key={item}><CheckCircle2 size={14} /> {item}</span>
            ))}
          </div>

          <div className="landing-cta-row">
            <button className="landing-teal-btn" type="button" onClick={() => promptCreateAccount()} disabled={loading}>
              Start Free Scan <ArrowRight size={16} />
            </button>
            <button className="landing-light-btn" type="button">Book a Demo</button>
          </div>
        </div>

        <aside className="landing-auth-card" id="create-account">
          <AccountForm loading={loading} error={error} signupPrompt={signupPrompt} onSubmit={authenticate} />
        </aside>
      </section>

      {/* ── Stats bar ── */}
      <section className="landing-stats-bar">
        <div className="landing-stats-inner">
          {[
            { value: "40+", label: "Security checks" },
            { value: "3", label: "Scanner versions" },
            { value: "URL + Code", label: "Scan coverage" },
            { value: "PDF + JSON", label: "Report formats" },
          ].map(({ value, label }) => (
            <div className="landing-stat" key={label}>
              <strong>{value}</strong>
              <span>{label}</span>
            </div>
          ))}
        </div>
      </section>

      {/* ── Features grid ── */}
      <section className="landing-section" id="how-it-works">
        <SectionAccent type="rings" tone="light" className="accent-br" />
        <SectionAccent type="grid-dots" tone="light" className="accent-tl" />
        <div className="landing-section-inner">
          <div className="landing-section-head">
            <p className="landing-eyebrow"><Zap size={14} /> What we scan</p>
            <h2>Everything an attacker would look at</h2>
            <p>Two complementary scanners covering the full attack surface - from the outside in and from the source code out.</p>
          </div>
          <div className="landing-features-grid">
            {features.map(({ icon: Icon, title, desc }) => (
              <article className="landing-feature-card" key={title}>
                <div className="landing-feature-icon">
                  <Icon size={22} />
                </div>
                <strong>{title}</strong>
                <p>{desc}</p>
              </article>
            ))}
          </div>
        </div>
      </section>

      {/* ── Checks ticker ── */}
      <section className="landing-checks-section">
        <div className="landing-section-inner">
          <div className="landing-section-head">
            <p className="landing-eyebrow"><ShieldCheck size={14} /> Coverage</p>
            <h2>40+ security checks in every scan</h2>
          </div>
          <div className="landing-checks-grid">
            {checks.map((check) => (
              <div className="landing-check-pill" key={check}>
                <CheckCircle2 size={14} /> {check}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── How it works ── */}
      <section className="landing-section landing-section-alt" id="reports">
        <SectionAccent type="scanline" tone="mid" className="accent-tr" />
        <div className="landing-section-inner">
          <div className="landing-section-head">
            <p className="landing-eyebrow"><Activity size={14} /> How it works</p>
            <h2>From domain to report in minutes</h2>
            <p>No agents, no installs for URL scanning. Deep Scan runs one command on the client server.</p>
          </div>
          <div className="landing-steps-grid-wrap">
            <StepConnector />
            <div className="landing-steps-grid">
              {steps.map(({ step, title, desc }) => (
                <article className="landing-step-card" key={step}>
                  <div className="landing-step-num">{step}</div>
                  <strong>{title}</strong>
                  <p>{desc}</p>
                </article>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ── Report preview ── */}
      <section className="landing-section">
        <SectionAccent type="bracket" tone="light" className="accent-bl" />
        <div className="landing-section-inner landing-report-preview-wrap">
          <div className="landing-report-copy">
            <p className="landing-eyebrow"><FileText size={14} /> Reports</p>
            <h2>Engineer-ready reports, every scan</h2>
            <p>Every completed scan produces a structured report with severity ratings, evidence, and remediation steps. Download as PDF for clients or JSON for CI pipelines.</p>
            <ul className="landing-report-bullets">
              <li><CheckCircle2 size={15} /> Executive summary with risk score</li>
              <li><CheckCircle2 size={15} /> Per-finding evidence and remediation</li>
              <li><CheckCircle2 size={15} /> Codebase overview for deep scans</li>
              <li><CheckCircle2 size={15} /> PDF download for client delivery</li>
              <li><CheckCircle2 size={15} /> JSON export for CI/CD integration</li>
            </ul>
            <button className="landing-teal-btn" type="button" onClick={() => promptCreateAccount()}>
              Run a scan and get a report <ArrowRight size={16} />
            </button>
          </div>
          <div className="landing-report-mockup">
            <div className="lrm-bar">
              <span className="lrm-dot red" /><span className="lrm-dot amber" /><span className="lrm-dot green" />
              <span className="lrm-title">security-report-20260620.json</span>
            </div>
            <div className="lrm-body">
              <div className="lrm-line"><span className="lrm-key">"scanner"</span><span className="lrm-punc">:</span> <span className="lrm-str">"scan.sh v3"</span></div>
              <div className="lrm-line lrm-indent"><span className="lrm-key">"critical"</span><span className="lrm-punc">:</span> <span className="lrm-num">2</span></div>
              <div className="lrm-line lrm-indent"><span className="lrm-key">"high"</span><span className="lrm-punc">:</span> <span className="lrm-num lrm-high">14</span></div>
              <div className="lrm-line lrm-indent"><span className="lrm-key">"medium"</span><span className="lrm-punc">:</span> <span className="lrm-num">9</span></div>
              <div className="lrm-line lrm-indent"><span className="lrm-key">"total"</span><span className="lrm-punc">:</span> <span className="lrm-num">25</span></div>
              <div className="lrm-divider" />
              <div className="lrm-finding lrm-critical">
                <span className="lrm-badge">CRITICAL</span>
                <span>Hardcoded AWS key in .env</span>
              </div>
              <div className="lrm-finding lrm-high">
                <span className="lrm-badge">HIGH</span>
                <span>subprocess shell=True injection</span>
              </div>
              <div className="lrm-finding lrm-high">
                <span className="lrm-badge">HIGH</span>
                <span>Missing Content-Security-Policy</span>
              </div>
              <div className="lrm-finding lrm-medium">
                <span className="lrm-badge">MEDIUM</span>
                <span>TLS certificate expires in 18 days</span>
              </div>
              <div className="lrm-finding lrm-medium">
                <span className="lrm-badge">MEDIUM</span>
                <span>Wildcard CORS origin allowed</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── Pricing ── */}
      <section className="landing-section landing-section-dark" id="pricing">
        <NetworkMeshBackground variant="dark" density="medium" />
        <div className="landing-section-inner">
          <div className="landing-section-head landing-section-head-light">
            <p className="landing-eyebrow landing-eyebrow-light"><Zap size={14} /> Pricing</p>
            <h2>Simple, transparent plans</h2>
            <p>Start free with URL scanning. Upgrade when you need monitoring or source-code coverage.</p>
          </div>
          <div className="landing-pricing-grid">
            {plans.map(({ name, eyebrow, badge, description, features: planFeatures, cta, highlight }) => (
              <article className={`landing-pricing-card${highlight ? " landing-pricing-highlight" : ""}`} key={name}>
                {highlight ? <div className="landing-pricing-popular">Most popular</div> : null}
                <div className="lp-eyebrow">{eyebrow}</div>
                <strong className="lp-name">{name}</strong>
                <div className="lp-badge">{badge}</div>
                <p className="lp-desc">{description}</p>
                <ul className="lp-features">
                  {planFeatures.map((f) => (
                    <li key={f}><CheckCircle2 size={14} /> {f}</li>
                  ))}
                </ul>
                <button
                  className={highlight ? "landing-teal-btn" : "landing-light-btn"}
                  type="button"
                  onClick={() => promptCreateAccount()}
                >
                  {cta} <ArrowRight size={15} />
                </button>
              </article>
            ))}
          </div>
        </div>
      </section>

      {/* ── Final CTA ── */}
      <section className="landing-section landing-cta-section">
        <SectionAccent type="rings" tone="mid" className="accent-tr" />
        <div className="landing-section-inner landing-cta-inner">
          <div className="landing-cta-copy">
            <h2>Ready to see your attack surface?</h2>
            <p>Run a free scan now. No credit card, no install required. Scan time varies by site size.</p>
          </div>
          <div className="landing-cta-btns">
            <button className="landing-teal-btn landing-teal-btn-lg" type="button" onClick={() => promptCreateAccount()}>
              Start Free Scan <ArrowRight size={18} />
            </button>
            <button className="landing-light-btn" type="button">Book a Demo</button>
          </div>
        </div>
      </section>

      {/* ── Footer ── */}
      <footer className="landing-footer">
        <div className="landing-footer-inner">
          <div className="landing-footer-brand">
            <a className="landing-logo" href="/">
              <span><img src={shieldLogo} alt="" /></span>
              <strong>Security Tool</strong>
            </a>
            <p>Automated security assessment for web applications and source code.</p>
          </div>
          <div className="landing-footer-links">
            <strong>Product</strong>
            <a href="#features">Features</a>
            <a href="#how-it-works">How it works</a>
            <a href="#pricing">Pricing</a>
            <a href="#reports">Reports</a>
          </div>
          <div className="landing-footer-links">
            <strong>Company</strong>
            <a href="https://handsintechnology.in" target="_blank" rel="noreferrer">Hands In Technology</a>
            <a href="#">Contact</a>
            <a href="#">Privacy Policy</a>
          </div>
        </div>
        <div className="landing-footer-bottom">
          <span>© {new Date().getFullYear()} Hands In Technology. All rights reserved.</span>
          <span>Powered by Security Tool</span>
        </div>
      </footer>

    </main>
  );
}

function AccountForm({ loading, error, signupPrompt, onSubmit }) {
  const [mode, setMode] = useState("signin");
  const [showPassword, setShowPassword] = useState(false);
  const [values, setValues] = useState({
    email: "",
    password: "",
    first_name: "",
    last_name: "",
    company_name: "",
    company_url: "",
  });

  function updateValue(key, value) {
    setValues((current) => ({ ...current, [key]: value }));
  }

  function submit(event) {
    event.preventDefault();
    const password = values.password;
    const validPassword = /^(?=.*[A-Za-z])(?=.*\d).+$/.test(password);
    if (!validPassword) return;
    const payload = { email: values.email.trim(), password };
    if (mode === "signup") {
      payload.first_name = values.first_name.trim();
      payload.last_name = values.last_name.trim();
      payload.company_name = values.company_name.trim();
      payload.company_url = values.company_url.trim();
    }
    onSubmit(mode, payload);
  }

  useEffect(() => {
    if (signupPrompt) setMode("signup");
  }, [signupPrompt]);

  return (
    <>
      <div className="landing-card-head" id="account-access">
        <p>Account access</p>
        <h2>{mode === "signin" ? "Sign in" : "Create account"}</h2>
        <span>{mode === "signin" ? "Sign in to load your scans, findings, reports, and plan usage." : "Create an account if you do not have one yet."}</span>
      </div>

      <div className="landing-auth-toggle" role="group" aria-label="Account mode">
        <button className={mode === "signin" ? "active" : ""} type="button" onClick={() => setMode("signin")}>Sign in</button>
        <button className={mode === "signup" ? "active" : ""} type="button" onClick={() => setMode("signup")}>Create account</button>
      </div>

      <form className="landing-auth-fields" onSubmit={submit}>
        {mode === "signup" ? (
          <div className="landing-name-grid">
            <label>
              First name
              <span><UserRound size={18} /><input value={values.first_name} onChange={(e) => updateValue("first_name", e.target.value)} placeholder="Ayush" required /></span>
            </label>
            <label>
              Last name
              <span><UserRound size={18} /><input value={values.last_name} onChange={(e) => updateValue("last_name", e.target.value)} placeholder="Rana" /></span>
            </label>
          </div>
        ) : null}
        <label>
          Work email
          <span><Mail size={18} /><input value={values.email} onChange={(e) => updateValue("email", e.target.value)} placeholder="you@company.com" type="email" required /></span>
        </label>
        <label>
          Password
          <span className="landing-password-field">
            <LockKeyhole size={18} />
            <input
              value={values.password}
              onChange={(e) => updateValue("password", e.target.value)}
              placeholder="Minimum 8 characters"
              type={showPassword ? "text" : "password"}
              minLength={8}
              pattern="(?=.*[A-Za-z])(?=.*[0-9]).{8,}"
              title="Use at least 8 characters with letters and numbers."
              required
            />
            <button className="landing-password-toggle" type="button" onClick={() => setShowPassword((v) => !v)} aria-label={showPassword ? "Hide password" : "Show password"}>
              {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
            </button>
          </span>
          <small className="landing-field-note">Use at least 8 characters with letters and numbers.</small>
        </label>
        {mode === "signup" ? (
          <>
            <label>
              Company name
              <span><ShieldCheck size={18} /><input value={values.company_name} onChange={(e) => updateValue("company_name", e.target.value)} placeholder="Hands In Technology" /></span>
            </label>
            <label>
              Company URL
              <span><Search size={18} /><input value={values.company_url} onChange={(e) => updateValue("company_url", e.target.value)} placeholder="https://company.com" type="url" /></span>
            </label>
          </>
        ) : null}
        <button className="landing-teal-btn" type="submit" disabled={loading}>
          {loading ? "Checking..." : mode === "signin" ? "Sign in" : "Create account"} <ArrowRight size={17} />
        </button>
        {mode === "signin" ? (
          <button className="landing-light-btn" type="button" onClick={() => setMode("signup")} disabled={loading}>
            Create account if you do not have one
          </button>
        ) : (
          <button className="landing-light-btn" type="button" onClick={() => setMode("signin")} disabled={loading}>
            <LockKeyhole size={17} /> Already have an account? Sign in
          </button>
        )}
        {error ? <p className="landing-error">{error}</p> : null}
      </form>

      <div className="landing-plan-note">
        <p>Basic Plan</p>
        <strong>5 scans</strong>
        <span>Available after account creation</span>
      </div>
    </>
  );
}

// ─────────────────────────────────────────────────────────────
// SectionAccent — static SVG decorative geometry per section
// tone: "light" | "mid" | "dark"
// type: "rings" | "scanline" | "bracket" | "grid-dots"
// ─────────────────────────────────────────────────────────────
function SectionAccent({ type = "rings", tone = "light", className = "" }) {
  const tealLight  = "rgba(0,127,122,0.07)";
  const tealMid    = "rgba(0,127,122,0.11)";
  const tealDark   = "rgba(0,127,122,0.18)";
  const c = tone === "dark" ? tealDark : tone === "mid" ? tealMid : tealLight;

  if (type === "rings") {
    return (
      <svg aria-hidden="true" focusable="false" className={`section-accent ${className}`}
        viewBox="0 0 320 320" xmlns="http://www.w3.org/2000/svg">
        <circle cx="320" cy="320" r="120" fill="none" stroke={c} strokeWidth="1" />
        <circle cx="320" cy="320" r="180" fill="none" stroke={c} strokeWidth="1" />
        <circle cx="320" cy="320" r="240" fill="none" stroke={c} strokeWidth="1" />
        <circle cx="320" cy="320" r="8" fill={c} />
        <circle cx="320" cy="320" r="18" fill="none" stroke={c} strokeWidth="1" />
      </svg>
    );
  }
  if (type === "scanline") {
    return (
      <svg aria-hidden="true" focusable="false" className={`section-accent ${className}`}
        viewBox="0 0 280 200" xmlns="http://www.w3.org/2000/svg">
        {Array.from({ length: 7 }, (_, i) => (
          <line key={i} x1="0" y1={i * 28 + 14} x2="280" y2={i * 28 + 14}
            stroke={c} strokeWidth="1" />
        ))}
        {Array.from({ length: 5 }, (_, i) => (
          <line key={i} x1={i * 56 + 28} y1="0" x2={i * 56 + 28} y2="200"
            stroke={c} strokeWidth="1" />
        ))}
        <rect x="112" y="56" width="56" height="56" fill="none" stroke={c} strokeWidth="1.5" />
        <circle cx="140" cy="84" r="4" fill={c} />
      </svg>
    );
  }
  if (type === "bracket") {
    return (
      <svg aria-hidden="true" focusable="false" className={`section-accent ${className}`}
        viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg">
        <path d="M180 20 L120 20 L120 80" fill="none" stroke={c} strokeWidth="2" strokeLinecap="round" />
        <path d="M20 180 L80 180 L80 120" fill="none" stroke={c} strokeWidth="2" strokeLinecap="round" />
        <circle cx="120" cy="80" r="3" fill={c} />
        <circle cx="80" cy="120" r="3" fill={c} />
        <line x1="120" y1="80" x2="80" y2="120" stroke={c} strokeWidth="1" strokeDasharray="5 6" />
      </svg>
    );
  }
  if (type === "grid-dots") {
    const pts = [];
    for (let row = 0; row < 4; row++)
      for (let col = 0; col < 5; col++)
        pts.push({ x: col * 44 + 22, y: row * 44 + 22 });
    return (
      <svg aria-hidden="true" focusable="false" className={`section-accent ${className}`}
        viewBox="0 0 220 176" xmlns="http://www.w3.org/2000/svg">
        {pts.map((p, i) => <circle key={i} cx={p.x} cy={p.y} r="2" fill={c} />)}
      </svg>
    );
  }
  return null;
}

// ─────────────────────────────────────────────────────────────
// NetworkMeshBackground
// ─────────────────────────────────────────────────────────────
function seededRandom(seed) {
  let s = seed;
  return function () {
    s = (s * 1664525 + 1013904223) & 0xffffffff;
    return (s >>> 0) / 0xffffffff;
  };
}

function generateNodes(width, height, count, seed) {
  const rng = seededRandom(seed);
  const nodes = [];
  // Keep nodes in left 65% of width so they don't bleed under the auth card
  for (let i = 0; i < count; i++) {
    nodes.push({
      x: rng() * width * 0.65,
      y: rng() * height,
    });
  }
  return nodes;
}

function buildEdges(nodes, maxDist) {
  const edges = [];
  const connected = new Set();
  for (let i = 0; i < nodes.length; i++) {
    let nearest = [];
    for (let j = 0; j < nodes.length; j++) {
      if (i === j) continue;
      const dx = nodes[i].x - nodes[j].x;
      const dy = nodes[i].y - nodes[j].y;
      const dist = Math.sqrt(dx * dx + dy * dy);
      if (dist < maxDist) nearest.push({ j, dist });
    }
    nearest.sort((a, b) => a.dist - b.dist);
    // Connect to 1-2 nearest
    nearest.slice(0, 2).forEach(({ j }) => {
      const key = i < j ? `${i}-${j}` : `${j}-${i}`;
      if (!connected.has(key)) {
        connected.add(key);
        edges.push([nodes[i], nodes[j]]);
      }
    });
  }
  return edges;
}

function NetworkMeshBackground({ variant = "light", density = "medium" }) {
  const W = 900;
  const H = 560;
  const nodeCount = density === "low" ? 22 : 36;
  const maxDist = density === "low" ? 180 : 220;
  // Balanced: dots subtle, lines visible enough to read as a graph
  const dotR       = variant === "dark" ? 2   : 1.8;
  const dotOpacity = variant === "dark" ? 0.22 : 0.10;
  const lineW      = variant === "dark" ? 1.2 : 1;
  const lineOpacity = variant === "dark" ? 0.20 : 0.12;
  const nodes = generateNodes(W, H, nodeCount, 42);
  const edges = buildEdges(nodes, maxDist);

  return (
    <svg
      className="mesh-bg"
      aria-hidden="true"
      focusable="false"
      xmlns="http://www.w3.org/2000/svg"
      viewBox={`0 0 ${W} ${H}`}
      preserveAspectRatio="xMidYMid slice"
    >
      <defs>
        {variant === "light" && (
          <linearGradient id="mesh-fade-h" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%"  stopColor="white" stopOpacity="1" />
            <stop offset="50%" stopColor="white" stopOpacity="1" />
            <stop offset="72%" stopColor="white" stopOpacity="0" />
          </linearGradient>
        )}
        {variant === "light" && (
          <mask id="mesh-mask-h">
            <rect width={W} height={H} fill="url(#mesh-fade-h)" />
          </mask>
        )}
      </defs>
      <g
        stroke="#007f7a"
        fill="#007f7a"
        mask={variant === "light" ? "url(#mesh-mask-h)" : undefined}
      >
        {edges.map(([a, b], i) => (
          <line
            key={i}
            x1={a.x} y1={a.y}
            x2={b.x} y2={b.y}
            strokeWidth={lineW}
            strokeOpacity={lineOpacity}
          />
        ))}
        {nodes.map((n, i) => (
          <circle
            key={i}
            cx={n.x} cy={n.y} r={dotR}
            fillOpacity={dotOpacity}
          />
        ))}
      </g>
    </svg>
  );
}

// ─────────────────────────────────────────────────────────────
// StepConnector — dashed SVG line linking the 4 How It Works cards
// ─────────────────────────────────────────────────────────────
function StepConnector({ count = 4 }) {
  const containerRef = useRef(null);
  const [segments, setSegments] = useState([]);

  useEffect(() => {
    function measure() {
      const container = containerRef.current;
      if (!container) return;
      const cards = Array.from(container.querySelectorAll(".landing-step-card"));
      if (cards.length < 2) return;
      const containerRect = container.getBoundingClientRect();
      const pts = cards.map((card) => {
        const r = card.getBoundingClientRect();
        return {
          x: r.left - containerRect.left + r.width / 2,
          y: r.top - containerRect.top + r.height / 2,
        };
      });
      // Only draw if cards are roughly in a row (horizontal layout)
      const isHorizontal = Math.abs(pts[0].y - pts[pts.length - 1].y) < 80;
      if (!isHorizontal) { setSegments([]); return; }
      const segs = [];
      for (let i = 0; i < pts.length - 1; i++) {
        segs.push({ x1: pts[i].x, y1: pts[i].y, x2: pts[i + 1].x, y2: pts[i + 1].y });
      }
      setSegments(segs);
    }
    measure();
    const ro = new ResizeObserver(measure);
    if (containerRef.current) ro.observe(containerRef.current);
    return () => ro.disconnect();
  }, []);

  return (
    <div className="step-connector-wrap" ref={containerRef}>
      {segments.length > 0 && (
        <svg
          className="step-connector-svg"
          aria-hidden="true"
          focusable="false"
          style={{ position: "absolute", inset: 0, width: "100%", height: "100%", pointerEvents: "none", zIndex: 0 }}
        >
          <defs>
            <marker id="sc-arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
              <path d="M0,0 L0,6 L7,3 z" fill="#007f7a" fillOpacity="0.18" />
            </marker>
          </defs>
          {segments.map((s, i) => (
            <line
              key={i}
              x1={s.x1} y1={s.y1}
              x2={s.x2} y2={s.y2}
              stroke="#007f7a"
              strokeOpacity="0.15"
              strokeWidth="1.5"
              strokeDasharray="6 8"
              markerEnd="url(#sc-arrow)"
            />
          ))}
        </svg>
      )}
    </div>
  );
}

export default LandingGate;
