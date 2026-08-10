import { useEffect, useMemo, useState, type FormEvent } from "react";

import { Api, ApiError, type Page, type RecordBase } from "./api";
import { authConfig, authManager, currentUser, devSignIn, signOut, type AuthUser, type DevPersona } from "./auth";

type Context = {
  tenant: { id: string; name: string };
  principal: { id: string; name: string; type: string };
  role: string | null;
  permissions: string[];
};
type Application = RecordBase & { name: string; description: string; criticality: number; internet_exposed: boolean };
type Finding = RecordBase & { title: string; severity: number; confidence: number; status: string; cwe: string };
type Threat = RecordBase & { stride_category: string; scenario: string; likelihood: number; impact: number; status: string };
type Assessment = RecordBase & { name: string; status: string };
type Risk = RecordBase & { title: string; state: string };
type DeploymentTarget = RecordBase & { name: string; provider: string; environment: string; state: string };
type DeploymentDecision = RecordBase & {
  target: string;
  decision: string;
  risk_score: string;
  compliance_score: string;
  reason_codes: string[];
  superseded_by: string | null;
  integrity_verified?: boolean;
};
type TenantSummary = RecordBase & { name: string; slug: string; tenant_type: string; isolation_tier: string };
type Engagement = RecordBase & { name: string; reference: string; status: string; starts_on: string; ends_on: string };
type OrganisationControl = RecordBase & { unified_control: string; status: string; implementation_score: string };
type ComplianceGap = RecordBase & { title: string; severity: number; status: string };
type Task = RecordBase & { title: string; status: string; due_at: string | null };
type Evidence = RecordBase & { title: string; status: string; content_hash: string };
type Entitlement = RecordBase & { code: string; enabled: boolean; limit: number | null };
type Usage = RecordBase & { metric: string; quantity: number; recorded_at: string };
type EvaluationRun = RecordBase & { target: string; state: string; error_code: string; summary: Record<string, number> };
type ControlResult = RecordBase & { outcome: string; reason_code: string; resource_type: string; resource_id: string; gap: string | null; risk: string | null };
type EvidenceArtifact = RecordBase & { role: string; sha256: string; size_bytes: number };
type Waiver = RecordBase & { status: string; expires_at: string; resource_fingerprint: string };
type WorkflowState = { state: string; version: number; events: string[] };
type WorkflowTransition = {
  id: string; event: string; from_state: string; to_state: string; actor_id: string;
  reason: string; entity_version: number; occurred_at: string;
};

const EMPTY_PAGE = { results: [], next: null, previous: null };

export function severityLabel(value: number): string {
  return ["Info", "Low", "Moderate", "High", "Critical", "Critical"][value] ?? "Unknown";
}

/** Map a gate decision onto the existing severity palette. */
export function decisionSeverity(decision: string): number {
  return { blocked: 5, error: 4, manual_review: 3, approved_with_actions: 2, approved: 0 }[decision] ?? 3;
}

export function decisionLabel(decision: string): string {
  return decision.replaceAll("_", " ");
}

export function isTerminalState(state: string): boolean {
  return ["completed", "failed", "cancelled"].includes(state);
}

function Login({ error, onLogin }: { error?: string; onLogin: (user: AuthUser) => void }) {
  const [personas, setPersonas] = useState<DevPersona[] | null>(null);
  useEffect(() => { void authConfig().then((value) => setPersonas(value.dev_auth_enabled ? value.dev_personas : null)); }, []);
  return (
    <main className="login-shell">
      <section className="login-panel" aria-labelledby="login-title">
        <div className="mark" aria-hidden="true">त्रि</div>
        <p className="eyebrow">ONE PLATFORM · THREE DIMENSIONS</p>
        <h1 id="login-title">AI Trishul</h1>
        <p>Evidence-backed security intelligence for code, architecture, and assurance.</p>
        {error && <div className="error" role="alert">{error}</div>}
        {personas ? <label>Local persona<select defaultValue="" onChange={(event) => {
          const persona = personas.find((item) => item.username === event.target.value);
          if (persona) onLogin(devSignIn(persona));
        }}><option value="" disabled>Select a persona</option>{personas.map((persona) => <option key={persona.username} value={persona.username}>{persona.label} · {persona.tenant_name}</option>)}</select></label>
          : <button onClick={() => void authManager().then((value) => value.signinRedirect())}>Sign in with enterprise identity</button>}
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

function DeploymentWizard({ api, applications, targets, onCreated }: { api: Api; applications: Application[]; targets: DeploymentTarget[]; onCreated: () => void }) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  async function createTarget(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setMessage("");
    const values = new FormData(event.currentTarget);
    try {
      await api.create("assurance/deployment-targets/", {
        application: values.get("application"), name: values.get("name"), slug: values.get("slug"),
        provider: values.get("provider"), target_type: "iac_deployment", environment: values.get("environment"),
        external_id: values.get("external_id"), criticality: 3, data_sensitivity: 3,
      });
      setMessage("Deployment target registered."); onCreated(); event.currentTarget.reset();
    } catch (reason) { setMessage(reason instanceof Error ? reason.message : "Target registration failed."); }
    finally { setBusy(false); }
  }

  async function evaluate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setMessage("");
    const values = new FormData(event.currentTarget);
    const artifact = values.get("artifact");
    if (!(artifact instanceof File)) { setBusy(false); setMessage("Choose an artifact."); return; }
    const body = new FormData(); body.set("target", String(values.get("target"))); body.set("source_type", String(values.get("source_type"))); body.set("artifact", artifact);
    try {
      const snapshot = await api.request<RecordBase>("assurance/deployment-snapshots/", { method: "POST", body });
      const accepted = await api.create<{ evaluation_run_id: string }>(`assurance/deployment-snapshots/${snapshot.id}/evaluations/`, { trigger: "manual" });
      setMessage(`Evaluation ${accepted.evaluation_run_id} queued.`); onCreated(); event.currentTarget.reset();
    } catch (reason) { setMessage(reason instanceof Error ? reason.message : "Evaluation submission failed."); }
    finally { setBusy(false); }
  }

  return <div className="two-column">
    <form className="wizard" onSubmit={createTarget}><h3>Register target</h3>
      <label>Application<select name="application" required>{applications.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
      <label>Name<input name="name" required /></label><label>Slug<input name="slug" required pattern="[a-z0-9-]+" /></label>
      <label>Provider<select name="provider"><option>aws</option><option>azure</option><option>gcp</option><option>on_premises</option></select></label>
      <label>Environment<select name="environment"><option>production</option><option>staging</option><option>development</option></select></label>
      <label>External ID<input name="external_id" required /></label><button disabled={busy}>Register target</button>
    </form>
    <form className="wizard" onSubmit={evaluate}><h3>Submit evidence</h3>
      <label>Target<select name="target" required>{targets.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
      <label>Artifact type<select name="source_type"><option value="terraform_plan">Terraform plan</option><option value="kubernetes_manifest">Kubernetes manifest</option><option value="compose_file">Compose file</option><option value="server_inventory">Server inventory</option></select></label>
      <label>Artifact<input name="artifact" type="file" required /></label><button disabled={busy}>Submit evaluation</button>
    </form>
    {message && <p role="status">{message}</p>}
  </div>;
}

function SaaSAction({ api, role, onCreated }: { api: Api; role: string | null; onCreated: () => void }) {
  const [message, setMessage] = useState("");
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); const values = new FormData(event.currentTarget); setMessage("");
    try {
      if (role === "platform_admin") {
        await api.create("tenant-admin/", { slug: values.get("slug"), name: values.get("name"), administrator_email: values.get("email"), plan_key: "pilot", entitlements: { auditor_seats: 10, auditee_organisations: 10, frameworks: ["ISO/IEC 27002:2022"], evidence_bytes: 1_000_000_000, deployment_evaluations: 1000, ai_credits: 100000, connectors: true, vendor_assessments: true } });
      } else {
        await api.create("engagements/onboard-auditee/", { slug: values.get("slug"), name: values.get("name"), administrator_email: values.get("email"), auditee_mode: "firm_managed" });
      }
      setMessage("Organisation created and administrator invited."); onCreated(); event.currentTarget.reset();
    } catch (reason) { setMessage(reason instanceof Error ? reason.message : "Onboarding failed."); }
  }
  if (!["platform_admin", "firm_admin", "audit_manager"].includes(role ?? "")) return null;
  return <form className="wizard" onSubmit={submit}><h3>{role === "platform_admin" ? "Create audit firm" : "Onboard auditee"}</h3>
    <label>Name<input name="name" required /></label><label>Slug<input name="slug" required pattern="[a-z0-9-]+" /></label>
    <label>Administrator email<input name="email" type="email" required /></label><button>Create and invite</button>{message && <p role="status">{message}</p>}
  </form>;
}

function EngagementWizard({ api, role, onCreated }: { api: Api; role: string | null; onCreated: () => void }) {
  const [message, setMessage] = useState("");
  if (!["firm_admin", "audit_manager"].includes(role ?? "")) return null;
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); const values = new FormData(event.currentTarget);
    try {
      await api.create("engagements/", { auditee_tenant: values.get("auditee"), name: values.get("name"), reference: values.get("reference"), status: "active", starts_on: values.get("starts"), ends_on: values.get("ends"), framework_scope: [values.get("framework")], application_scope: String(values.get("application") ?? "").split(",").map((item) => item.trim()).filter(Boolean), control_scope: [] });
      setMessage("Engagement created."); onCreated(); event.currentTarget.reset();
    } catch (reason) { setMessage(reason instanceof Error ? reason.message : "Engagement creation failed."); }
  }
  return <form className="wizard" onSubmit={submit}><h3>Create engagement</h3><label>Auditee tenant UUID<input name="auditee" required /></label>
    <label>Name<input name="name" required /></label><label>Reference<input name="reference" required /></label>
    <label>Starts<input name="starts" type="date" required /></label><label>Ends<input name="ends" type="date" required /></label>
    <label>Framework<input name="framework" defaultValue="ISO/IEC 27002:2022" required /></label><label>Application UUIDs (comma-separated)<input name="application" /></label>
    <button>Create engagement</button>{message && <p role="status">{message}</p>}
  </form>;
}

function WorkflowActions({ api, path, item, onChanged }: {
  api: Api; path: string; item: RecordBase; onChanged: () => void;
}) {
  const [workflow, setWorkflow] = useState<WorkflowState>();
  const [timeline, setTimeline] = useState<WorkflowTransition[]>();
  const [reason, setReason] = useState("");
  const [message, setMessage] = useState("");

  useEffect(() => {
    let active = true;
    void api.request<WorkflowState>(`${path}/${item.id}/available-transitions/`)
      .then((value) => { if (active) setWorkflow(value); })
      .catch(() => { if (active) setWorkflow(undefined); });
    return () => { active = false; };
  }, [api, path, item.id, item.version]);

  async function advance(event: string) {
    setMessage("");
    if (["close", "revoke"].includes(event) && !reason.trim()) {
      setMessage("A reason is required."); return;
    }
    try {
      await api.request(`${path}/${item.id}/transition/`, {
        method: "POST",
        headers: { "If-Match": String(workflow?.version ?? item.version), "Idempotency-Key": crypto.randomUUID() },
        body: JSON.stringify({ event, reason }),
      });
      onChanged();
    } catch (error) {
      setMessage(error instanceof ApiError && error.status === 412 ? "State changed; refresh and try again." : error instanceof Error ? error.message : "Transition failed.");
    }
  }

  async function loadTimeline() {
    try { setTimeline(await api.request<WorkflowTransition[]>(`${path}/${item.id}/timeline/`)); }
    catch (error) { setMessage(error instanceof Error ? error.message : "Timeline unavailable."); }
  }

  if (!workflow?.events.length && !timeline) return <button className="secondary" onClick={() => void loadTimeline()}>History</button>;
  return <div>
    {!!workflow?.events.length && <div className="actions">
      {workflow.events.map((event) => <button key={event} type="button" onClick={() => void advance(event)}>{decisionLabel(event)}</button>)}
      {workflow.events.some((event) => ["close", "revoke"].includes(event)) && <label>Reason<input value={reason} onChange={(event) => setReason(event.target.value)} maxLength={4000} /></label>}
    </div>}
    <button className="secondary" type="button" onClick={() => void loadTimeline()}>History</button>
    {message && <small role="alert">{message}</small>}
    {timeline && <ol aria-label="Workflow history">{timeline.map((entry) => <li key={entry.id}><strong>{decisionLabel(entry.event)}</strong> {entry.from_state || "imported"} → {entry.to_state}<small>{new Date(entry.occurred_at).toLocaleString()} · {entry.reason}</small></li>)}</ol>}
  </div>;
}

function Dashboard({ user }: { user: AuthUser }) {
  const [tenantId, setTenantId] = useState(localStorage.getItem("trishul.tenant") ?? "");
  const [context, setContext] = useState<Context | null>(null);
  const [error, setError] = useState("");
  const [refresh, setRefresh] = useState(0);
  const [applications, setApplications] = useState<Page<Application>>(EMPTY_PAGE);
  const [findings, setFindings] = useState<Page<Finding>>(EMPTY_PAGE);
  const [threats, setThreats] = useState<Page<Threat>>(EMPTY_PAGE);
  const [assessments, setAssessments] = useState<Page<Assessment>>(EMPTY_PAGE);
  const [risks, setRisks] = useState<Page<Risk>>(EMPTY_PAGE);
  const [targets, setTargets] = useState<Page<DeploymentTarget>>(EMPTY_PAGE);
  const [decisions, setDecisions] = useState<Page<DeploymentDecision>>(EMPTY_PAGE);
  const [firms, setFirms] = useState<TenantSummary[]>([]);
  const [engagements, setEngagements] = useState<Page<Engagement>>(EMPTY_PAGE);
  const [controls, setControls] = useState<Page<OrganisationControl>>(EMPTY_PAGE);
  const [gaps, setGaps] = useState<Page<ComplianceGap>>(EMPTY_PAGE);
  const [tasks, setTasks] = useState<Page<Task>>(EMPTY_PAGE);
  const [evidence, setEvidence] = useState<Page<Evidence>>(EMPTY_PAGE);
  const [entitlements, setEntitlements] = useState<Page<Entitlement>>(EMPTY_PAGE);
  const [usage, setUsage] = useState<Page<Usage>>(EMPTY_PAGE);
  const [runs, setRuns] = useState<Page<EvaluationRun>>(EMPTY_PAGE);
  const [controlResults, setControlResults] = useState<Page<ControlResult>>(EMPTY_PAGE);
  const [artifacts, setArtifacts] = useState<Page<EvidenceArtifact>>(EMPTY_PAGE);
  const [waivers, setWaivers] = useState<Page<Waiver>>(EMPTY_PAGE);
  const [outcomeFilter, setOutcomeFilter] = useState("all");
  const [loading, setLoading] = useState(true);
  const api = useMemo(() => new Api(user, tenantId), [user, tenantId]);

  useEffect(() => {
    let active = true;
    async function load() {
      setLoading(true);
      try {
        const [nextContext, appPage, findingPage, threatPage, assessmentPage, riskPage] = await Promise.all([
          api.request<Context>("context"), api.list<Application>("applications/"), api.list<Finding>("findings/"),
          api.list<Threat>("threats/"), api.list<Assessment>("assessments/"), api.list<Risk>("risks/"),
        ]);
        if (!active) return;
        setContext(nextContext); setApplications(appPage); setFindings(findingPage); setThreats(threatPage); setAssessments(assessmentPage); setRisks(riskPage); setError("");
        // Deployment Assurance is a separately permissioned module: a role
        // without its grants must still get a working dashboard, so these
        // requests degrade to empty rather than failing the whole load.
        const [targetPage, decisionPage] = await Promise.all([
          api.list<DeploymentTarget>("assurance/deployment-targets/").catch(() => EMPTY_PAGE as Page<DeploymentTarget>),
          api.list<DeploymentDecision>("assurance/deployment-decisions/").catch(() => EMPTY_PAGE as Page<DeploymentDecision>),
        ]);
        if (!active) return;
        setTargets(targetPage); setDecisions(decisionPage);
        const empty = <T,>() => EMPTY_PAGE as Page<T>;
        const [firmRows, engagementPage, controlPage, gapPage, taskPage, evidencePage, entitlementPage, usagePage, runPage, resultPage, artifactPage, waiverPage] = await Promise.all([
          api.request<TenantSummary[]>("tenant-admin/").catch(() => []),
          api.list<Engagement>("engagements/").catch(() => empty<Engagement>()),
          api.list<OrganisationControl>("organisation-controls/").catch(() => empty<OrganisationControl>()),
          api.list<ComplianceGap>("compliance-gaps/").catch(() => empty<ComplianceGap>()),
          api.list<Task>("tasks/").catch(() => empty<Task>()), api.list<Evidence>("evidence/").catch(() => empty<Evidence>()),
          api.list<Entitlement>("tenant-entitlements/").catch(() => empty<Entitlement>()),
          api.list<Usage>("usage-records/").catch(() => empty<Usage>()),
          api.list<EvaluationRun>("assurance/evaluation-runs/").catch(() => empty<EvaluationRun>()),
          api.list<ControlResult>("assurance/control-results/").catch(() => empty<ControlResult>()),
          api.list<EvidenceArtifact>("assurance/evidence-artifacts/").catch(() => empty<EvidenceArtifact>()),
          api.list<Waiver>("assurance/exception-waivers/").catch(() => empty<Waiver>()),
        ]);
        if (!active) return;
        setFirms(firmRows); setEngagements(engagementPage); setControls(controlPage); setGaps(gapPage); setTasks(taskPage);
        setEvidence(evidencePage); setEntitlements(entitlementPage); setUsage(usagePage); setRuns(runPage);
        setControlResults(resultPage); setArtifacts(artifactPage); setWaivers(waiverPage);
        if (!tenantId) { setTenantId(nextContext.tenant.id); localStorage.setItem("trishul.tenant", nextContext.tenant.id); }
      } catch (reason) {
        if (active) setError(reason instanceof ApiError ? reason.message : "Unable to load security intelligence.");
      } finally {
        if (active) setLoading(false);
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
        <nav aria-label="Primary"><a href="#overview">Overview</a><a href="#saas">Tenants & engagements</a><a href="#compliance">Compliance posture</a><a href="#applications">Applications</a><a href="#deployments">Deployment assurance</a><a href="#findings">Code findings</a><a href="#risks">Risk intelligence</a></nav>
        <button className="secondary logout" onClick={() => void signOut(user)}>Sign out</button>
      </aside>
      <main>
        <header><div><p className="eyebrow">SECURITY INTELLIGENCE</p><h1 id="overview">{context?.tenant.name ?? "AI Trishul"}</h1></div><div className="identity"><span>{context?.principal.name ?? user.profile.name ?? user.profile.sub}</span><small>{context?.role ?? "authenticated"}</small></div></header>
        {error && <section className="error" role="alert"><strong>Access requires a valid tenant membership.</strong><span>{error}</span><label>Tenant ID<input value={tenantId} onChange={(event) => changeTenant(event.target.value)} placeholder="UUID from your administrator" /></label></section>}
        {loading && <p className="loading-inline" role="status">Loading tenant posture…</p>}
        <section className="score-grid" aria-label="Security overview">
          <article><span>Applications</span><strong>{applications.results.length}</strong></article>
          <article><span>Open findings</span><strong>{findings.results.filter((item) => item.status !== "resolved").length}</strong></article>
          <article><span>Open threats</span><strong>{threats.results.filter((item) => item.status === "open" || item.status === "draft").length}</strong></article>
          <article><span>Active risks</span><strong>{risks.results.filter((item) => item.state !== "closed").length}</strong></article>
          <article><span>Blocked deployments</span><strong>{decisions.results.filter((item) => !item.superseded_by && item.decision === "blocked").length}</strong></article>
          <article><span>Open critical gaps</span><strong>{gaps.results.filter((item) => item.status !== "closed" && item.severity >= 4).length}</strong></article>
        </section>
        <section className="panel" id="saas"><div className="section-title"><div><p className="eyebrow">SAAS OPERATIONS</p><h2>Tenants and engagements</h2></div><span>{engagements.results.filter((item) => item.status === "active").length} active engagements</span></div>
          <div className="two-column"><SaaSAction api={api} role={context?.role ?? null} onCreated={() => setRefresh((value) => value + 1)} /><EngagementWizard api={api} role={context?.role ?? null} onCreated={() => setRefresh((value) => value + 1)} /></div>
          {!!firms.length && <table><thead><tr><th>Audit firm</th><th>Isolation</th></tr></thead><tbody>{firms.map((item) => <tr key={item.id}><td><strong>{item.name}</strong><small>{item.slug}</small></td><td>{decisionLabel(item.isolation_tier)}</td></tr>)}</tbody></table>}
          {!!engagements.results.length && <table><thead><tr><th>Engagement</th><th>Window</th><th>Status</th><th>Workflow</th></tr></thead><tbody>{engagements.results.map((item) => <tr key={item.id}><td><strong>{item.name}</strong><small>{item.reference}</small></td><td>{item.starts_on} – {item.ends_on}</td><td>{item.status}</td><td><WorkflowActions api={api} path="engagements" item={item} onChanged={() => setRefresh((value) => value + 1)} /></td></tr>)}</tbody></table>}
          {!firms.length && !engagements.results.length && <p className="empty">No tenant administration or assigned audit work is available for this role.</p>}
          {!!entitlements.results.length && <p className="quiet">Entitlements: {entitlements.results.map((item) => `${item.code}=${item.enabled ? item.limit ?? "enabled" : "disabled"}`).join(" · ")}</p>}
          {!!usage.results.length && <p className="quiet">Latest usage: {usage.results.slice(0, 6).map((item) => `${item.metric} ${item.quantity}`).join(" · ")}</p>}
        </section>
        <section className="panel" id="compliance"><div className="section-title"><div><p className="eyebrow">CISO SUMMARY</p><h2>Governance and compliance posture</h2></div><span>{evidence.results.length} evidence records</span></div>
          <div className="score-grid"><article><span>Controls requiring attention</span><strong>{controls.results.filter((item) => !["compliant", "not_applicable"].includes(item.status)).length}</strong></article><article><span>Open gaps</span><strong>{gaps.results.filter((item) => item.status !== "closed").length}</strong></article><article><span>Open tasks</span><strong>{tasks.results.filter((item) => item.status !== "completed").length}</strong></article><article><span>Active risks</span><strong>{risks.results.filter((item) => item.state !== "closed").length}</strong></article></div>
          <div className="two-column"><div><h3>Organisation controls</h3>{controls.results.slice(0, 8).map((item) => <article className="item" key={item.id}><div><strong>{item.unified_control}</strong><small>{decisionLabel(item.status)}</small></div><WorkflowActions api={api} path="organisation-controls" item={item} onChanged={() => setRefresh((value) => value + 1)} /></article>)}{!controls.results.length && <p className="empty">No controls have evidence yet.</p>}</div><div><h3>Remediation tasks</h3>{tasks.results.slice(0, 8).map((item) => <article className="item" key={item.id}><div><strong>{item.title}</strong><small>{item.due_at ?? "No due date"}</small></div><span>{decisionLabel(item.status)}</span></article>)}{!tasks.results.length && <p className="empty">No remediation work is open.</p>}</div></div>
        </section>
        <section className="panel" id="applications"><div className="section-title"><div><p className="eyebrow">PORTFOLIO</p><h2>Applications</h2></div><AppWizard api={api} onCreated={() => setRefresh((value) => value + 1)} /></div><table><thead><tr><th>Name</th><th>Criticality</th><th>Exposure</th></tr></thead><tbody>{applications.results.map((item) => <tr key={item.id}><td><strong>{item.name}</strong><small>{item.description}</small></td><td>{severityLabel(item.criticality)}</td><td>{item.internet_exposed ? "Internet" : "Internal"}</td></tr>)}</tbody></table>{!applications.results.length && <p className="empty">No applications registered.</p>}</section>
        <section className="panel" id="deployments">
          <div className="section-title"><div><p className="eyebrow">DEPLOYMENT ASSURANCE</p><h2>Latest gate decisions</h2></div><span>{targets.results.filter((item) => item.state === "active").length} active targets</span></div>
          <DeploymentWizard api={api} applications={applications.results} targets={targets.results} onCreated={() => setRefresh((value) => value + 1)} />
          <h3>Evaluation history</h3>
          <table><thead><tr><th>Run</th><th>State</th><th>Result</th><th>Workflow</th></tr></thead><tbody>{runs.results.slice(0, 10).map((item) => <tr key={item.id}><td><strong>{item.id.slice(0, 8)}</strong><small>{item.created_at}</small></td><td>{isTerminalState(item.state) ? item.state : `In progress: ${item.state}`}</td><td>{item.error_code || (item.summary ? `${item.summary.fail ?? 0} failed` : "Pending")}</td><td><WorkflowActions api={api} path="assurance/evaluation-runs" item={item} onChanged={() => setRefresh((value) => value + 1)} /></td></tr>)}</tbody></table>
          {!runs.results.length && <p className="empty">No evaluation runs yet.</p>}
          <table><thead><tr><th>Target</th><th>Environment</th><th>Compliance</th><th>Risk</th><th>Decision</th></tr></thead><tbody>
            {decisions.results.filter((item) => !item.superseded_by).map((item) => {
              const target = targets.results.find((candidate) => candidate.id === item.target);
              return (
                <tr key={item.id}>
                  <td><strong>{target?.name ?? "Unknown target"}</strong><small>{item.reason_codes.join(", ").toLowerCase().replaceAll("_", " ")}{item.integrity_verified === false ? " · integrity failed" : ""}</small></td>
                  <td>{target?.environment ?? "—"}</td>
                  <td>{item.compliance_score}%</td>
                  <td>{item.risk_score}</td>
                  <td><span className={`severity severity-${decisionSeverity(item.decision)}`}>{decisionLabel(item.decision)}</span></td>
                </tr>
              );
            })}
          </tbody></table>
          {!decisions.results.length && <p className="empty">No deployment has been evaluated yet.</p>}
          <div className="section-title"><h3>Control results</h3><label>Outcome <select value={outcomeFilter} onChange={(event) => setOutcomeFilter(event.target.value)}><option value="all">All</option><option value="fail">Fail</option><option value="manual_review">Manual review</option><option value="pass">Pass</option><option value="not_evaluated">Not evaluated</option></select></label></div>
          {controlResults.results.filter((item) => outcomeFilter === "all" || item.outcome === outcomeFilter).slice(0, 20).map((item) => <article className="item" key={item.id}><div><strong>{item.reason_code}</strong><small>{item.resource_type} · {item.resource_id}{item.gap ? ` · gap ${item.gap.slice(0, 8)}` : ""}{item.risk ? ` · risk ${item.risk.slice(0, 8)}` : ""}</small></div><span className={`severity severity-${decisionSeverity(item.outcome === "fail" ? "blocked" : item.outcome === "manual_review" ? "manual_review" : "approved")}`}>{decisionLabel(item.outcome)}</span></article>)}
          <div className="two-column"><div><h3>Evidence references</h3>{artifacts.results.slice(0, 8).map((item) => <article className="item" key={item.id}><div><strong>{decisionLabel(item.role)}</strong><small>sha256 {item.sha256.slice(0, 16)}… · {item.size_bytes} bytes</small></div></article>)}{!artifacts.results.length && <p className="empty">No immutable assurance evidence.</p>}</div><div><h3>Waivers</h3>{waivers.results.slice(0, 8).map((item) => <article className="item" key={item.id}><div><strong>{item.status}</strong><small>Expires {item.expires_at} · {item.resource_fingerprint.slice(0, 12)}…</small></div></article>)}{!waivers.results.length && <p className="empty">No exception waivers.</p>}</div></div>
        </section>
        <div className="two-column">
          <section className="panel" id="findings"><p className="eyebrow">CODE REVIEW</p><h2>Findings</h2>{findings.results.map((item) => <article className="item" key={item.id}><div><strong>{item.title}</strong><small>{item.cwe || "Unmapped"} · {item.status.replaceAll("_", " ")}</small></div><span className={`severity severity-${item.severity}`}>{severityLabel(item.severity)}</span></article>)}{!findings.results.length && <p className="empty">No evidence-backed findings.</p>}</section>
          <section className="panel" id="threats"><p className="eyebrow">ARCHITECTURE</p><h2>Threats</h2>{threats.results.map((item) => <article className="item" key={item.id}><div><strong>{item.stride_category}</strong><small>{item.scenario}</small></div><span>{item.status}</span></article>)}{!threats.results.length && <p className="empty">No reviewed threats.</p>}</section>
          <section className="panel" id="assessments"><p className="eyebrow">ASSURANCE</p><h2>Assessments</h2>{assessments.results.map((item) => <article className="item" key={item.id}><strong>{item.name}</strong><span>{item.status}</span></article>)}{!assessments.results.length && <p className="empty">No assessments started.</p>}</section>
          <section className="panel" id="risks"><p className="eyebrow">PRIORITY</p><h2>Risk intelligence</h2>{risks.results.map((item) => <article className="item" key={item.id}><strong>{item.title}</strong><span>{item.state}</span></article>)}{!risks.results.length && <p className="empty">No correlated risks.</p>}</section>
        </div>
      </main>
    </div>
  );
}

export default function App() {
  const [user, setUser] = useState<AuthUser | null>();
  const [error, setError] = useState("");
  useEffect(() => { void currentUser().then(setUser).catch((reason) => { setError(reason instanceof Error ? reason.message : "Sign-in failed."); setUser(null); }); }, []);
  if (user === undefined) return <main className="loading">Loading secure workspace…</main>;
  return user ? <Dashboard user={user} /> : <Login error={error} onLogin={setUser} />;
}

