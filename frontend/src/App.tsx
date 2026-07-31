import { useEffect, useMemo, useState, type FormEvent } from "react";
import type { User } from "oidc-client-ts";

import { Api, ApiError, type Page, type RecordBase } from "./api";
import { authManager, currentUser } from "./auth";

type Context = {
  tenant: { id: string; name: string };
  principal: { id: string; name: string; type: string };
  role: string | null;
  permissions: string[];
};
type Application = RecordBase & { name: string; description: string; criticality: number; internet_exposed: boolean };
type Finding = RecordBase & { title: string; severity: number; confidence: number; status: string; cwe: string; ai_advisory?: { label: string; summary: string; suggested_remediation: string } };
type Threat = RecordBase & { stride_category: string; scenario: string; likelihood: number; impact: number; status: string };
type Assessment = RecordBase & { name: string; status: string };
type Risk = RecordBase & { title: string; state: string };

const EMPTY_PAGE = { results: [], next: null, previous: null };

export function severityLabel(value: number): string {
  return ["Info", "Low", "Moderate", "High", "Critical", "Critical"][value] ?? "Unknown";
}

export function advisorySummary(advisory?: Finding["ai_advisory"]): string | null {
  return advisory?.summary ? `${advisory.label}: ${advisory.summary}` : null;
}

function Login({ error }: { error?: string }) {
  return (
    <main className="login-shell">
      <section className="login-panel" aria-labelledby="login-title">
        <div className="mark" aria-hidden="true">त्रि</div>
        <p className="eyebrow">ONE PLATFORM · THREE DIMENSIONS</p>
        <h1 id="login-title">AI Trishul</h1>
        <p>Evidence-backed security intelligence for code, architecture, and assurance.</p>
        {error && <div className="error" role="alert">{error}</div>}
        <button onClick={() => void authManager().then((value) => value.signinRedirect())}>Sign in with enterprise identity</button>
      </section>
    </main>
  );
}

function AppWizard({ api, onCreated }: { api: Api; onCreated: () => void }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    const values = new FormData(event.currentTarget);
    try {
      const organization = await api.create<RecordBase>("organizations/", { name: values.get("organization") });
      const workspace = await api.create<RecordBase>("workspaces/", {
        organization: organization.id,
        name: values.get("workspace"),
      });
      await api.create("applications/", {
        workspace: workspace.id,
        name: values.get("application"),
        description: values.get("description"),
        criticality: Number(values.get("criticality")),
      });
      setOpen(false);
      onCreated();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Application registration failed.");
    } finally {
      setBusy(false);
    }
  }

  if (!open) return <button onClick={() => setOpen(true)}>Register application</button>;
  return (
    <form className="wizard" onSubmit={submit}>
      <h2>Register application</h2>
      <label>Organization<input name="organization" required maxLength={200} /></label>
      <label>Workspace<input name="workspace" required maxLength={200} /></label>
      <label>Application<input name="application" required maxLength={200} /></label>
      <label>Description<textarea name="description" maxLength={4000} /></label>
      <label>Business criticality<select name="criticality" defaultValue="3"><option value="1">Low</option><option value="3">High</option><option value="5">Critical</option></select></label>
      {error && <div className="error" role="alert">{error}</div>}
      <div className="actions"><button disabled={busy}>{busy ? "Registering…" : "Register"}</button><button type="button" className="secondary" onClick={() => setOpen(false)}>Cancel</button></div>
    </form>
  );
}

function Dashboard({ user }: { user: User }) {
  const [tenantId, setTenantId] = useState(localStorage.getItem("trishul.tenant") ?? "");
  const [context, setContext] = useState<Context | null>(null);
  const [error, setError] = useState("");
  const [refresh, setRefresh] = useState(0);
  const [applications, setApplications] = useState<Page<Application>>(EMPTY_PAGE);
  const [findings, setFindings] = useState<Page<Finding>>(EMPTY_PAGE);
  const [threats, setThreats] = useState<Page<Threat>>(EMPTY_PAGE);
  const [assessments, setAssessments] = useState<Page<Assessment>>(EMPTY_PAGE);
  const [risks, setRisks] = useState<Page<Risk>>(EMPTY_PAGE);
  const api = useMemo(() => new Api(user, tenantId), [user, tenantId]);

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const [nextContext, appPage, findingPage, threatPage, assessmentPage, riskPage] = await Promise.all([
          api.request<Context>("context"), api.list<Application>("applications/"), api.list<Finding>("findings/"),
          api.list<Threat>("threats/"), api.list<Assessment>("assessments/"), api.list<Risk>("risks/"),
        ]);
        if (!active) return;
        setContext(nextContext); setApplications(appPage); setFindings(findingPage); setThreats(threatPage); setAssessments(assessmentPage); setRisks(riskPage); setError("");
        if (!tenantId) { setTenantId(nextContext.tenant.id); localStorage.setItem("trishul.tenant", nextContext.tenant.id); }
      } catch (reason) {
        if (active) setError(reason instanceof ApiError ? reason.message : "Unable to load security intelligence.");
      }
    }
    void load();
    return () => { active = false; };
  }, [api, refresh, tenantId]);

  function changeTenant(value: string) {
    const clean = value.trim();
    localStorage.setItem("trishul.tenant", clean);
    setTenantId(clean);
  }

  return (
    <div className="app-shell">
      <aside>
        <div className="brand"><span className="brand-mark">त्रि</span><span>AI Trishul</span></div>
        <nav aria-label="Primary"><a href="#overview">Overview</a><a href="#applications">Applications</a><a href="#findings">Code findings</a><a href="#threats">Threat models</a><a href="#assessments">Assessments</a><a href="#risks">Risk intelligence</a></nav>
        <button className="secondary logout" onClick={() => void authManager().then((value) => value.signoutRedirect())}>Sign out</button>
      </aside>
      <main>
        <header><div><p className="eyebrow">SECURITY INTELLIGENCE</p><h1 id="overview">{context?.tenant.name ?? "AI Trishul"}</h1></div><div className="identity"><span>{context?.principal.name ?? user.profile.name ?? user.profile.sub}</span><small>{context?.role ?? "authenticated"}</small></div></header>
        {error && <section className="error" role="alert"><strong>Access requires a valid tenant membership.</strong><span>{error}</span><label>Tenant ID<input value={tenantId} onChange={(event) => changeTenant(event.target.value)} placeholder="UUID from your administrator" /></label></section>}
        <section className="score-grid" aria-label="Security overview">
          <article><span>Applications</span><strong>{applications.results.length}</strong></article>
          <article><span>Open findings</span><strong>{findings.results.filter((item) => item.status !== "resolved").length}</strong></article>
          <article><span>Open threats</span><strong>{threats.results.filter((item) => item.status === "open" || item.status === "draft").length}</strong></article>
          <article><span>Active risks</span><strong>{risks.results.filter((item) => item.state !== "closed").length}</strong></article>
        </section>
        <section className="panel" id="applications"><div className="section-title"><div><p className="eyebrow">PORTFOLIO</p><h2>Applications</h2></div><AppWizard api={api} onCreated={() => setRefresh((value) => value + 1)} /></div><table><thead><tr><th>Name</th><th>Criticality</th><th>Exposure</th></tr></thead><tbody>{applications.results.map((item) => <tr key={item.id}><td><strong>{item.name}</strong><small>{item.description}</small></td><td>{severityLabel(item.criticality)}</td><td>{item.internet_exposed ? "Internet" : "Internal"}</td></tr>)}</tbody></table>{!applications.results.length && <p className="empty">No applications registered.</p>}</section>
        <div className="two-column">
          <section className="panel" id="findings"><p className="eyebrow">CODE REVIEW</p><h2>Findings</h2>{findings.results.map((item) => <article className="item" key={item.id}><div><strong>{item.title}</strong><small>{item.cwe || "Unmapped"} · {item.status.replaceAll("_", " ")}</small>{advisorySummary(item.ai_advisory) && <small>{advisorySummary(item.ai_advisory)}</small>}</div><span className={`severity severity-${item.severity}`}>{severityLabel(item.severity)}</span></article>)}{!findings.results.length && <p className="empty">No evidence-backed findings. AI enrichment is optional and may be disabled.</p>}</section>
          <section className="panel" id="threats"><p className="eyebrow">ARCHITECTURE</p><h2>Threats</h2>{threats.results.map((item) => <article className="item" key={item.id}><div><strong>{item.stride_category}</strong><small>{item.scenario}</small></div><span>{item.status}</span></article>)}{!threats.results.length && <p className="empty">No reviewed threats.</p>}</section>
          <section className="panel" id="assessments"><p className="eyebrow">ASSURANCE</p><h2>Assessments</h2>{assessments.results.map((item) => <article className="item" key={item.id}><strong>{item.name}</strong><span>{item.status}</span></article>)}{!assessments.results.length && <p className="empty">No assessments started.</p>}</section>
          <section className="panel" id="risks"><p className="eyebrow">PRIORITY</p><h2>Risk intelligence</h2>{risks.results.map((item) => <article className="item" key={item.id}><strong>{item.title}</strong><span>{item.state}</span></article>)}{!risks.results.length && <p className="empty">No correlated risks.</p>}</section>
        </div>
      </main>
    </div>
  );
}

export default function App() {
  const [user, setUser] = useState<User | null>();
  const [error, setError] = useState("");
  useEffect(() => { void currentUser().then(setUser).catch((reason) => { setError(reason instanceof Error ? reason.message : "Sign-in failed."); setUser(null); }); }, []);
  if (user === undefined) return <main className="loading">Loading secure workspace…</main>;
  return user ? <Dashboard user={user} /> : <Login error={error} />;
}
