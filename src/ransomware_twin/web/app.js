"use strict";

const PROFILE_IDS = ["flat-baseline", "segmented-only", "least-privilege-only", "immutable-backup-only", "resilient-reference"];
const byId = (id) => document.getElementById(id);

async function request(path, options = {}) {
  const response = await fetch(path, options);
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.detail || payload.error || `HTTP ${response.status}`);
  return payload;
}

function fillList(element, values) {
  element.replaceChildren();
  values.forEach((value) => {
    const item = document.createElement("li");
    item.textContent = value;
    element.append(item);
  });
}

function metricList(element, metrics) {
  element.replaceChildren();
  const values = [
    ["Data lost", `${metrics.data_lost_percent.toFixed(1)}%`],
    ["RTO / RPO", `${metrics.rto_minutes} / ${metrics.rpo_minutes} min`],
    ["Exfiltration", `${metrics.exfiltrated_data_gb.toFixed(1)} GB`],
    ["Blast radius", `${metrics.blast_radius_percent.toFixed(1)}%`],
  ];
  values.forEach(([label, value]) => {
    const term = document.createElement("dt");
    const description = document.createElement("dd");
    term.textContent = label;
    description.textContent = value;
    element.append(term, description);
  });
}

function render(comparison) {
  const reports = Object.fromEntries(comparison.reports.map((item) => [item.profile.id, item]));
  const baseline = reports["flat-baseline"];
  const resilient = reports["resilient-reference"];
  byId("base-title").textContent = baseline.profile.label;
  byId("hard-title").textContent = resilient.profile.label;
  byId("base-touched").textContent = `${baseline.metrics.machines_touched}/${baseline.metrics.total_assets}`;
  byId("hard-touched").textContent = `${resilient.metrics.machines_touched}/${resilient.metrics.total_assets}`;
  metricList(byId("base-metrics"), baseline.metrics);
  metricList(byId("hard-metrics"), resilient.metrics);
  byId("digest").textContent = comparison.functional_sha256;

  const body = byId("profile-body");
  body.replaceChildren();
  comparison.reports.forEach((report) => {
    const metrics = report.metrics;
    const row = document.createElement("tr");
    const values = [
      report.profile.label,
      `${metrics.machines_touched}/${metrics.total_assets}`,
      metrics.encrypted_assets,
      metrics.time_to_confinement_seconds === null ? "n/a" : `${metrics.time_to_confinement_seconds} s`,
      `${metrics.exfiltrated_data_gb.toFixed(1)} GB`,
      `${metrics.data_lost_percent.toFixed(1)}%`,
      `${metrics.rto_minutes}/${metrics.rpo_minutes} min`,
      `${metrics.blast_radius_percent.toFixed(1)}%`,
      metrics.resilience_score.toFixed(1),
    ];
    values.forEach((value, index) => {
      const cell = document.createElement("td");
      cell.textContent = String(value);
      if (index === 8) cell.className = metrics.resilience_score >= 90 ? "good" : metrics.resilience_score < 50 ? "bad" : "warn";
      row.append(cell);
    });
    body.append(row);
  });

  const relevantControls = new Set(["segmentation-policy", "least-privilege-policy", "immutable-recovery-policy", "automated-containment"]);
  const controlLines = comparison.reports.flatMap((report) => Object.entries(report.metrics.blocked_events_by_control)
    .filter(([reason]) => relevantControls.has(reason))
    .map(([reason, count]) => `${report.profile.label} · ${reason}: ${count} events`));
  fillList(byId("controls"), controlLines);
  byId("timeline-label").textContent = resilient.profile.label;
  const timeline = byId("timeline");
  timeline.replaceChildren();
  resilient.events.forEach((event) => {
    const line = document.createElement("div");
    line.className = `event ${event.stage === "defense" ? "defense" : event.outcome}`;
    line.textContent = `T+${String(event.at_seconds).padStart(3, "0")}s · ${event.stage} · ${event.primitive} · ${event.outcome} · ${event.reason}`;
    timeline.append(line);
  });
}

async function run() {
  const button = byId("run");
  const error = byId("error");
  button.disabled = true;
  error.hidden = true;
  try {
    const comparison = await request("/api/v1/compare", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({profile_ids: PROFILE_IDS}),
    });
    render(comparison);
  } catch (reason) {
    error.textContent = reason instanceof Error ? reason.message : String(reason);
    error.hidden = false;
  } finally {
    button.disabled = false;
  }
}

async function boot() {
  try {
    const [health, topology] = await Promise.all([request("/api/v1/health"), request("/api/v1/topology")]);
    byId("health").textContent = health.status === "ok" ? "READY / SAFE" : "UNAVAILABLE";
    const assets = topology.topology.assets;
    fillList(byId("topology"), [
      `${assets.length} systems across ${new Set(assets.map((item) => item.zone)).size} zones`,
      `${assets.filter((item) => item.kind === "workstation").length} user workstations`,
      `${assets.filter((item) => ["identity", "file-share", "business-service"].includes(item.kind)).length} identity, data, and business systems`,
      `${topology.topology.paths.length} controlled access paths`,
      `${topology.topology.dependencies.length} declared service dependencies`,
    ]);
    byId("run").addEventListener("click", run);
    await run();
  } catch (reason) {
    byId("health").textContent = "UNAVAILABLE";
    byId("error").textContent = reason instanceof Error ? reason.message : String(reason);
    byId("error").hidden = false;
  }
}

window.addEventListener("DOMContentLoaded", boot);
