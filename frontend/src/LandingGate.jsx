import {
  ArrowRight,
  CheckCircle2,
  Eye,
  EyeOff,
  Globe2,
  LockKeyhole,
  Mail,
  Menu,
  Search,
  ShieldCheck,
  UserRound,
  X,
} from "lucide-react";
import { useEffect, useState } from "react";
import { apiUrl, authHeaders, clearStoredAuth, getStoredAuth, storeAuth } from "./api.js";
import DashboardApp from "./App.jsx";
import shieldLogo from "./assets/shield.png";

const capabilities = [
  "Attack Surface Discovery",
  "Exposure Detection",
  "Security Validation",
  "PDF Reports",
];

const navItems = ["Features", "Capabilities", "Reports", "Pricing"];

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
      setError(authError.message || "Could not sign in. Confirm the backend and app auth are configured.");
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

  if (showDashboard) {
    return <DashboardApp onLogout={handleLogout} />;
  }

  if (bootstrapping) {
    return null;
  }

  return (
    <main className="landing-shell">
      <header className="landing-nav-wrap">
        <nav className="landing-nav">
          <a className="landing-logo" href="/">
            <span><img src={shieldLogo} alt="" /></span>
            <strong>Security Tool</strong>
          </a>

          <div className="landing-nav-links">
            {navItems.map((item) => (
              <a href={`#${item.toLowerCase()}`} key={item}>{item}</a>
            ))}
          </div>

          <div className="landing-nav-actions">
            <button type="button" onClick={() => document.getElementById("account-access")?.scrollIntoView({ behavior: "smooth", block: "center" })} disabled={loading}>
              Sign in
            </button>
            <button className="landing-dark-btn" type="button" onClick={() => promptCreateAccount()} disabled={loading}>
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
            <button type="button" onClick={() => document.getElementById("account-access")?.scrollIntoView({ behavior: "smooth", block: "center" })}>Sign in</button>
            <button type="button" onClick={() => promptCreateAccount()}>Start Free Scan</button>
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

          <form className="landing-url-bar" onSubmit={(event) => { event.preventDefault(); promptCreateAccount("Create an account to run a scan for this domain and keep the findings in your workspace."); }}>
            <Globe2 size={21} />
            <input placeholder="https://your-company.com" type="url" aria-label="Website URL" />
            <button type="submit" disabled={loading}>
              Start Scan <ArrowRight size={17} />
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
            {capabilities.map((item) => (
              <span key={item}><CheckCircle2 size={15} /> {item}</span>
            ))}
          </div>

          <div className="landing-cta-row">
            <button className="landing-dark-btn" type="button" onClick={() => promptCreateAccount()} disabled={loading}>Start Free Scan</button>
            <button className="landing-light-btn" type="button">Book Demo</button>
          </div>
        </div>

        <aside className="landing-auth-card" id="create-account">
          <AccountForm loading={loading} error={error} signupPrompt={signupPrompt} onSubmit={authenticate} />
        </aside>
      </section>
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

    const payload = {
      email: values.email.trim(),
      password,
    };
    if (mode === "signup") {
      payload.first_name = values.first_name.trim();
      payload.last_name = values.last_name.trim();
      payload.company_name = values.company_name.trim();
      payload.company_url = values.company_url.trim();
    }
    onSubmit(mode, payload);
  }

  useEffect(() => {
    if (signupPrompt) {
      setMode("signup");
    }
  }, [signupPrompt]);

  return (
    <>
      <div className="landing-card-head" id="account-access">
        <p>Account access</p>
        <h2>{mode === "signin" ? "Sign in" : "Create account"}</h2>
        <span>{mode === "signin" ? "Sign in to load your scans, findings, reports, and plan usage." : "Create an account if you do not have one yet."}</span>
      </div>

      <div className="landing-auth-toggle" role="group" aria-label="Account mode">
        <button className={mode === "signin" ? "active" : ""} type="button" onClick={() => setMode("signin")}>
          Sign in
        </button>
        <button className={mode === "signup" ? "active" : ""} type="button" onClick={() => setMode("signup")}>
          Create account
        </button>
      </div>

      <form className="landing-auth-fields" onSubmit={submit}>
        {mode === "signup" ? (
          <div className="landing-name-grid">
            <label>
              First name
              <span><UserRound size={18} /><input value={values.first_name} onChange={(event) => updateValue("first_name", event.target.value)} placeholder="Ayush" required /></span>
            </label>
            <label>
              Last name
              <span><UserRound size={18} /><input value={values.last_name} onChange={(event) => updateValue("last_name", event.target.value)} placeholder="Rana" /></span>
            </label>
          </div>
        ) : null}
        <label>
          Work email
          <span><Mail size={18} /><input value={values.email} onChange={(event) => updateValue("email", event.target.value)} placeholder="you@company.com" type="email" required /></span>
        </label>
        <label>
          Password
          <span className="landing-password-field">
            <LockKeyhole size={18} />
            <input
              value={values.password}
              onChange={(event) => updateValue("password", event.target.value)}
              placeholder="Minimum 8 characters"
              type={showPassword ? "text" : "password"}
              minLength={8}
              pattern="(?=.*[A-Za-z])(?=.*[0-9]).{8,}"
              title="Use at least 8 characters with letters and numbers."
              required
            />
            <button
              className="landing-password-toggle"
              type="button"
              onClick={() => setShowPassword((current) => !current)}
              aria-label={showPassword ? "Hide password" : "Show password"}
            >
              {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
            </button>
          </span>
          <small className="landing-field-note">Use at least 8 characters with letters and numbers.</small>
        </label>
        {mode === "signup" ? (
          <>
            <label>
              Company name
              <span><ShieldCheck size={18} /><input value={values.company_name} onChange={(event) => updateValue("company_name", event.target.value)} placeholder="Hands In Technology" /></span>
            </label>
            <label>
              Company URL
              <span><Search size={18} /><input value={values.company_url} onChange={(event) => updateValue("company_url", event.target.value)} placeholder="https://company.com" type="url" /></span>
            </label>
          </>
        ) : null}
        <button className="landing-dark-btn" type="submit" disabled={loading}>
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

export default LandingGate;
