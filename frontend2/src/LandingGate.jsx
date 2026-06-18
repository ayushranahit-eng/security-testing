import {
  ArrowRight,
  CheckCircle2,
  FileText,
  Globe2,
  LockKeyhole,
  Menu,
  Radar,
  Search,
  ShieldCheck,
  UserRound,
  X,
} from "lucide-react";
import { useState } from "react";
import { apiUrl } from "./api.js";
import DashboardApp from "./App.jsx";

const capabilities = [
  "Attack Surface Discovery",
  "Exposure Detection",
  "Security Validation",
  "PDF Reports",
];

const navItems = ["Features", "Capabilities", "Reports", "Pricing"];

function LandingGate() {
  const [menuOpen, setMenuOpen] = useState(false);
  const [account, setAccount] = useState(null);
  const [showDashboard, setShowDashboard] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  if (showDashboard) {
    return <DashboardApp />;
  }

  async function verifyAccount() {
    setLoading(true);
    setError("");

    try {
      const response = await fetch(apiUrl("/api/me"));
      if (!response.ok) throw new Error("Account verification failed");
      setAccount(await response.json());
    } catch {
      setError("Could not verify account. Confirm the backend service is reachable and MongoDB is configured.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="landing-shell">
      <header className="landing-nav-wrap">
        <nav className="landing-nav">
          <a className="landing-logo" href="/">
            <span><Globe2 size={21} /></span>
            <strong>Security Tool</strong>
          </a>

          <div className="landing-nav-links">
            {navItems.map((item) => (
              <a href={`#${item.toLowerCase()}`} key={item}>{item}</a>
            ))}
          </div>

          <div className="landing-nav-actions">
            <button type="button" onClick={verifyAccount} disabled={loading}>
              {loading ? "Checking..." : "Login"}
            </button>
            <button className="landing-dark-btn" type="button" onClick={verifyAccount} disabled={loading}>
              Start Free Scan
            </button>
          </div>

          <button className="landing-menu-btn" type="button" onClick={() => setMenuOpen((value) => !value)} aria-label="Toggle menu">
            {menuOpen ? <X size={20} /> : <Menu size={20} />}
          </button>
        </nav>

        {menuOpen ? (
          <div className="landing-mobile-menu">
            {navItems.map((item) => (
              <a href={`#${item.toLowerCase()}`} key={item}>{item}</a>
            ))}
            <button type="button" onClick={verifyAccount}>Login</button>
            <button type="button" onClick={verifyAccount}>Start Free Scan</button>
          </div>
        ) : null}
      </header>

      <section className="landing-hero">
        <div className="landing-hero-copy">
          <p className="landing-pill">Automated public attack-surface and security assessment</p>
          <h1>
            <span>Find Security Risks</span>
            <span>Before Attackers Do</span>
          </h1>
          <p className="landing-subtitle">
            Automated public attack-surface discovery, exposure detection, vulnerability validation, and evidence-backed reporting.
          </p>

          <form className="landing-url-bar" onSubmit={(event) => { event.preventDefault(); verifyAccount(); }}>
            <Globe2 size={21} />
            <input placeholder="https://your-company.com" type="url" aria-label="Website URL" />
            <button type="submit" disabled={loading}>
              Start Scan <ArrowRight size={17} />
            </button>
          </form>

          <div className="landing-trust-row">
            {capabilities.map((item) => (
              <span key={item}><CheckCircle2 size={15} /> {item}</span>
            ))}
          </div>

          <div className="landing-cta-row">
            <button className="landing-dark-btn" type="button" onClick={verifyAccount} disabled={loading}>Start Free Scan</button>
            <button className="landing-light-btn" type="button">Book Demo</button>
          </div>
        </div>

        <aside className="landing-auth-card" id="create-account">
          {account ? (
            <VerifiedAccount account={account} onEnter={() => setShowDashboard(true)} />
          ) : (
            <AccountForm loading={loading} error={error} onVerify={verifyAccount} />
          )}
        </aside>
      </section>
    </main>
  );
}

function AccountForm({ loading, error, onVerify }) {
  return (
    <>
      <div className="landing-card-head">
        <p>Account access</p>
        <h2>Login or create account</h2>
        <span>Create an account to save domains, scans, findings, reports, and plan usage.</span>
      </div>

      <div className="landing-auth-fields">
        <label>
          Work email
          <span><UserRound size={18} /><input placeholder="you@company.com" type="email" /></span>
        </label>
        <label>
          Company URL
          <span><Search size={18} /><input placeholder="https://company.com" type="url" /></span>
        </label>
        <button className="landing-dark-btn" type="button" onClick={onVerify} disabled={loading}>
          {loading ? "Verifying..." : "Create Account"} <ArrowRight size={17} />
        </button>
        <button className="landing-light-btn" type="button" onClick={onVerify} disabled={loading}>
          <LockKeyhole size={17} /> Login
        </button>
        {error ? <p className="landing-error">{error}</p> : null}
      </div>

      <div className="landing-plan-note">
        <p>Basic Plan</p>
        <strong>5 scans</strong>
        <span>Available after account creation</span>
      </div>
    </>
  );
}

function VerifiedAccount({ account, onEnter }) {
  const plan = account.account_plan || {};
  const connected = account.persistence === "mongodb";

  return (
    <>
      <div className="landing-card-head">
        <p>Account verified</p>
        <h2>{account.first_name} {account.last_name}</h2>
        <span>{account.company_name}</span>
      </div>

      <div className="landing-verified-list">
        <div>
          <UserRound size={18} />
          <span>{account.email}</span>
        </div>
        <div>
          <ShieldCheck size={18} />
          <span>{connected ? "MongoDB connected" : "Memory mode"}</span>
        </div>
        <div>
          <Radar size={18} />
          <span>{plan.name || "Basic"} Plan · {account.scans_left ?? 0} scans left</span>
        </div>
        <div>
          <FileText size={18} />
          <span>{account.scans_used ?? 0} scans used</span>
        </div>
      </div>

      <button className="landing-dark-btn landing-enter-btn" type="button" onClick={onEnter}>
        Enter dashboard <ArrowRight size={17} />
      </button>
    </>
  );
}

export default LandingGate;
