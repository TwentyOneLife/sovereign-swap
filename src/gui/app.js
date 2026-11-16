"use strict";
// The API token is injected into the page as a body data attribute (not an inline <script>), so the
// Content-Security-Policy can forbid inline scripts entirely (script-src 'self').
const TOKEN = document.body.dataset.token;
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

// A swap is terminal once it can no longer change: it settled (done), timed out to a refund, or was
// abandoned before locking. The Swaps tab shows only live swaps; the History ledger shows only
// terminal ones. (Phases: Waiting/Locking/Locked/Claiming/Refunding are live.)
const TERMINAL_PHASES = ["done", "refunded", "abandoned"];
const isTerminal = (s) => TERMINAL_PHASES.includes(s.phase);

// ---- Chain display names: single source of truth ------------------------------------------------
// The Blake2b chain's ticker is NOT settled: nonkyc and the mining pools use BTCB2, some exchanges use
// XBT, and XBT also means Bitcoin elsewhere. So every user-facing chain name lives here, keyed by the
// wire chain id ('btc'/'xbtc', which never changes - the daemon API keeps using those). To rename the
// whole GUI (e.g. switch 'short' to BTCB2, or drop the proto suffix) edit THIS object only.
//   short: compact label for tables and the status row
//   long:  unambiguous form for detail panels, tooltips and prose
//   url:   the chain's official site, linked from the detail/donate panels
const CHAIN = {
  btc: {
    short: "BTC",
    long: "BTC (SHA256)",
    note: "Bitcoin (SHA256 proof-of-work)",
    url: "https://bitcoin.org/en/",
  },
  xbtc: {
    short: "B2B",
    long: "BTC (Blake2b)",
    note: "BTC (Blake2b), a separate asset and chain from BTC (SHA256)",
    url: "https://bitcoinknots.org/",
  },
};
const chainShort = (c) => (CHAIN[c] || {}).short || String(c).toUpperCase();
const chainLong = (c) => (CHAIN[c] || {}).long || String(c).toUpperCase();
const chainNote = (c) => (CHAIN[c] || {}).note || String(c).toUpperCase();
const chainUrl = (c) => (CHAIN[c] || {}).url || "";
// Compact chain label for terse table cells: the short tag (BTC / B2B) with the full name
// (BTC (SHA256) / BTC (Blake2b)) as a hover tooltip, so B2B is never a mystery abbreviation.
const chainTag = (c) => `<span title="${escapeHtml(chainLong(c))}">${escapeHtml(chainShort(c))}</span>`;
// The chain's long name as a link to its official site (detail/donate panels). External navigation is
// allowed under the CSP (script-src 'self' governs scripts, not <a> links).
const chainLink = (c) => {
  const u = chainUrl(c);
  const name = escapeHtml(chainLong(c));
  return u
    ? `<a href="${escapeHtml(u)}" target="_blank" rel="noopener noreferrer">${name}</a>`
    : name;
};

// Select-all-on-click for read-only copy fields. A single delegated listener replaces the per-element
// inline `onclick` handlers, which CSP (script-src 'self', no 'unsafe-inline') would otherwise block.
document.addEventListener("click", (e) => {
  const t = e.target;
  if (t && t.classList && t.classList.contains("copyable") && typeof t.select === "function") {
    t.select();
  }
});

async function api(method, path, body) {
  const r = await fetch(path, {
    method,
    headers: { Authorization: "Bearer " + TOKEN, "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await r.text();
  const data = text ? JSON.parse(text) : null;
  if (!r.ok) throw Object.assign(new Error("api"), { status: r.status, data });
  return data;
}

// Accept 0.5 and 0,5 (mirrors daemon::parse_btc_to_sats). Returns integer sats, or null.
function parseBtc(s) {
  s = s.trim();
  if (s.includes(".") && s.includes(",")) return null;
  s = s.replace(",", ".");
  if (!/^\d*\.?\d*$/.test(s) || s === "" || s === ".") return null;
  let [w, f = ""] = s.split(".");
  if (f.length > 8) return null;
  f = (f + "00000000").slice(0, 8);
  return Number(w || "0") * 1e8 + Number(f);
}
const fmtSats = (sat) => (sat / 1e8).toFixed(8).replace(/\.?0+$/, "");
// A rate (counter coin per unit) spans a huge range: roughly 0.004 BTC per xBTC one way, ~270 the
// other. Show enough significant digits for the small direction (where toFixed(4) rounded away the
// real xBTC/BTC price) without a wall of zeros for the large one (#89).
const fmtRate = (r) =>
  !isFinite(r) ? "?" : r >= 100 ? r.toFixed(2) : r >= 1 ? r.toFixed(4) : r.toFixed(8);

// Relative time ("3m ago") with the absolute local time on hover (#88 time columns).
function fmtTime(sec) {
  if (!sec) return { text: "-", title: "" };
  const d = new Date(sec * 1000);
  const diff = Date.now() / 1000 - sec;
  const text =
    diff < 60 ? "just now"
    : diff < 3600 ? Math.floor(diff / 60) + "m ago"
    : diff < 86400 ? Math.floor(diff / 3600) + "h ago"
    : Math.floor(diff / 86400) + "d ago";
  return { text, title: d.toLocaleString() };
}
// Relative time for a FUTURE instant (e.g. an offer expiry): "in 23h" / "in 2d", or "expired".
// fmtTime is "ago"-only, so a future timestamp would wrongly read "just now" (#260).
function fmtUntil(sec) {
  if (!sec) return "";
  const diff = sec - Date.now() / 1000;
  if (diff <= 0) return "expired";
  if (diff < 3600) return "in " + Math.round(diff / 60) + "m";
  if (diff < 86400) return "in " + Math.round(diff / 3600) + "h";
  return "in " + Math.round(diff / 86400) + "d";
}
const escapeHtml = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

// A sortable, paged (5/row) table with an inline expanding detail row, shared by Swaps and Market
// (#87). State lives on the <table> element. cfg: { columns:[{label,num?,get(row),cell(row)}], rows,
// rowId(row), actions(row)?=>html, wireActions(tr,row)?, detailInto(row, boxEl), defaultSort, defaultDir }.
const PAGE_SIZE = 5;
function mountTable(table, cfg) {
  const st = (table._v = table._v || {
    sort: cfg.defaultSort ?? 0,
    dir: cfg.defaultDir ?? "desc",
    page: 0,
    open: null,
  });
  st.cfg = cfg;
  renderTable(table);
}
function renderTable(table) {
  const st = table._v, cfg = st.cfg;
  const rows = [...cfg.rows].sort((a, b) => {
    const col = cfg.columns[st.sort], va = col.get(a), vb = col.get(b);
    const c = va < vb ? -1 : va > vb ? 1 : 0;
    return st.dir === "asc" ? c : -c;
  });
  const pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
  if (st.page >= pages) st.page = pages - 1;
  if (st.page < 0) st.page = 0;
  const pageRows = rows.slice(st.page * PAGE_SIZE, (st.page + 1) * PAGE_SIZE);
  const head = cfg.columns
    .map((c, i) => {
      const arrow = i === st.sort ? (st.dir === "asc" ? " ▲" : " ▼") : "";
      return `<th class="${c.num ? "num " : ""}sortable" data-i="${i}">${c.label}${arrow}</th>`;
    })
    .join("") + "<th></th>";
  let body = "";
  for (const row of pageRows) {
    const id = cfg.rowId(row);
    const tds = cfg.columns.map((c) => `<td class="${c.num ? "num" : ""}">${c.cell(row)}</td>`).join("");
    const act = cfg.actions ? cfg.actions(row) : "";
    body +=
      `<tr data-id="${id}">${tds}<td class="num">${act}` +
      `<button class="link detail-btn">${st.open === id ? "Hide ▲" : "Detail"}</button></td></tr>`;
    if (st.open === id) {
      body += `<tr class="detail-row"><td colspan="${cfg.columns.length + 1}"><div class="detail-box card">Loading…</div></td></tr>`;
    }
  }
  table.innerHTML = `<thead><tr>${head}</tr></thead><tbody>${body}</tbody>`;
  let pg = table.nextElementSibling;
  if (!pg || !pg.classList.contains("pager")) {
    pg = document.createElement("div");
    pg.className = "pager";
    table.after(pg);
  }
  pg.innerHTML =
    pages > 1
      ? `<button class="link" data-pg="-1" ${st.page === 0 ? "disabled" : ""}>‹ Prev</button>` +
        `<span class="muted">Page ${st.page + 1} of ${pages}</span>` +
        `<button class="link" data-pg="1" ${st.page >= pages - 1 ? "disabled" : ""}>Next ›</button>`
      : "";
  table.querySelectorAll("th.sortable").forEach((th) =>
    th.addEventListener("click", () => {
      const i = +th.dataset.i;
      if (st.sort === i) st.dir = st.dir === "asc" ? "desc" : "asc";
      else { st.sort = i; st.dir = "desc"; }
      renderTable(table);
    })
  );
  pg.querySelectorAll("[data-pg]").forEach((b) =>
    b.addEventListener("click", () => { st.page += +b.dataset.pg; renderTable(table); })
  );
  table.querySelectorAll("tr[data-id]").forEach((tr) => {
    const row = pageRows.find((r) => cfg.rowId(r) === tr.dataset.id);
    tr.querySelector(".detail-btn").addEventListener("click", (e) => {
      e.stopPropagation();
      st.open = st.open === tr.dataset.id ? null : tr.dataset.id;
      renderTable(table);
    });
    if (cfg.wireActions) cfg.wireActions(tr, row);
  });
  if (st.open) {
    const row = pageRows.find((r) => cfg.rowId(r) === st.open);
    const box = table.querySelector(".detail-box");
    if (row && box) cfg.detailInto(row, box);
  }
}

// --- tabs ---
$$(".tab").forEach((t) =>
  t.addEventListener("click", () => {
    $$(".tab").forEach((x) => x.classList.toggle("active", x === t));
    $$(".view").forEach((v) => v.classList.toggle("active", v.id === t.dataset.tab));
    refresh(t.dataset.tab);
  })
);

// --- status + dependency dots ---
// The connectivity dots come from /status (fast). The price dot comes from /reference-rate, which
// may do a Tor fetch, so it is loaded separately and never delays the other dots. Both feed one
// render from the last-known values.
let statusData = null; // last GET /status, or null when the daemon is unreachable
let priceState = "idle"; // "idle" (disabled) | "on" (rate available) | "err" (enabled, fetch failing)

function renderStatus() {
  const el = $("#status");
  if (!statusData) return; // loadStatus owns the "unreachable" text; don't clobber it from here
  const s = statusData;
  const onoff = (ok) => (ok ? "on" : "off");
  const priceTitle =
    priceState === "on"
      ? "External price reference (nonkyc BTCB2/BTC, over Tor): live"
      : priceState === "err"
        ? "External price reference: enabled, but the fetch is failing (often a blocked Tor exit; it retries)"
        : "External price reference: off (price discovery is this relay's order book)";
  // Each dot names the exact connection it reports, so a red dot points at the right place.
  const btcTitle = `${chainLong("btc")} node RPC: ${s.btc_node ? "reachable" : "unreachable"}`;
  const xbtcTitle = `${chainLong("xbtc")} node RPC: ${s.xbtc_node ? "reachable" : "unreachable"}`;
  const engineTitle = `Swap engine (the daemon's tick loop): ${s.engine ? "running" : "stopped"}`;
  // Connected sovereign-relays (your combined market, design 0029): list each with a tick/cross when
  // the daemon reports per-relay status, else fall back to the plain count.
  const relays = Array.isArray(s.relay_list) ? s.relay_list : [];
  const connectedRelays = relays.filter((r) => r.connected).length;
  const relayTitle = relays.length
    ? "Connected sovereign-relays (your market): " +
      relays.map((r) => `${escapeHtml(r.url)} ${r.connected ? "✓" : "✗"}`).join(", ")
    : `Nostr relay(s) for offer discovery: ${s.relays > 0 ? `${s.relays} connected` : "none connected"}`;
  const relayOk = relays.length ? connectedRelays > 0 : s.relays > 0;
  const relayLabel = relays.length ? `relays ${connectedRelays}/${relays.length}` : "relay";
  const activeTitle = `Swaps currently in flight on this node: ${s.active_swaps ?? "unknown"}`;
  // Each item groups its dot and label under one tooltip (hover either), and the items are spaced and
  // separated by a thin divider so a glance reads them apart instead of as one run-on string.
  const item = (cls, title, label) =>
    `<span class="stat" title="${title}"><span class="dot ${cls}"></span>${label}</span>`;
  const sep = `<span class="sep" aria-hidden="true">|</span>`;
  el.innerHTML = [
    item(onoff(s.btc_node), btcTitle, chainShort("btc")),
    item(onoff(s.xbtc_node), xbtcTitle, chainShort("xbtc")),
    item(onoff(s.engine), engineTitle, "engine"),
    item(onoff(relayOk), relayTitle, relayLabel),
    item(priceState, priceTitle, "price"),
    `<span class="stat" title="${activeTitle}">${s.active_swaps ?? "?"} active</span>`,
  ].join(sep);
  applyHealthGating();
}

// #253: what the last /status says we can safely do. Create offer and Take need the engine, both
// nodes, and at least one relay (an offer with no relay goes nowhere). Split needs the engine and
// both nodes but NOT the relay (it is a local on-chain action, no counterparty). Operator brakes
// (submit signed PSBT, Withdraw, Abort, Dismiss) are never gated: a relay drop mid-swap must not lock
// the user out of funding or teardown.
function health() {
  const s = statusData;
  if (!s) return { trade: false, split: false, reason: "the daemon is unreachable" };
  const relays = Array.isArray(s.relay_list) ? s.relay_list : [];
  const relayOk = relays.length ? relays.some((r) => r.connected) : s.relays > 0;
  const nodes = s.btc_node && s.xbtc_node;
  let reason = "";
  if (!s.engine) reason = "the swap engine is stopped";
  else if (!nodes) reason = "a chain node is unreachable";
  else if (!relayOk) reason = "no relay is connected";
  return { trade: !!(s.engine && nodes && relayOk), split: !!(s.engine && nodes), reason };
}
function gateBtn(el, ok, reason) {
  if (!el) return;
  if (el.dataset.basetitle === undefined) el.dataset.basetitle = el.title || "";
  el.disabled = !ok;
  el.title = ok
    ? el.dataset.basetitle
    : "Unavailable: " + reason + (el.dataset.basetitle ? " (" + el.dataset.basetitle + ")" : "");
}
function applyHealthGating() {
  const h = health();
  gateBtn($("#new-offer"), h.trade, h.reason);
  gateBtn($("#sp-classify"), h.split, h.reason);
  document.querySelectorAll(".take-btn, .take-btn2").forEach((b) => gateBtn(b, h.trade, h.reason));
}

async function loadStatus() {
  try {
    statusData = await api("GET", "/status");
    renderStatus();
  } catch (e) {
    statusData = null;
    $("#status").textContent = "daemon unreachable";
  }
}

// The external price reference health, for the header dot: off (disabled), on (a rate), or err
// (enabled but the fetch failed). A failing reference never blocks the other dots.
async function loadReference() {
  try {
    const r = await api("GET", "/reference-rate");
    priceState = !r.enabled ? "idle" : r.error ? "err" : "on";
  } catch (e) {
    priceState = "err";
  }
  renderStatus();
}

// --- market ---

// The maker's own offers (#211), with a Withdraw button each. Separate from the market table below,
// which lists other peers' offers.
async function loadMyOffers() {
  const wrap = $("#my-offers"), list = $("#my-offers-list"), msg = $("#my-offers-msg");
  const offers = await api("GET", "/my-offers").catch(() => []);
  if (!offers.length) { wrap.classList.add("hidden"); list.innerHTML = ""; msg.textContent = ""; return; }
  wrap.classList.remove("hidden");
  msg.textContent = "";
  list.innerHTML = offers.map((o) =>
    `<div class="row between" data-id="${escapeHtml(o.id)}" style="padding:.35rem 0;border-bottom:1px solid var(--line)">` +
    `<span>Selling <strong>${fmtSats(o.amount_sat)} ${chainShort(o.sell_chain)}</strong> for ` +
    `<strong>${fmtSats(o.counter_amount_sat)} ${chainShort(o.taker_chain)}</strong> · rate ${fmtRate(o.counter_amount_sat / o.amount_sat)}` +
    ` · posted ${o.seen_at ? escapeHtml(fmtTime(o.seen_at).text) : "unknown"}` +
    (o.valid_until ? ` · expires ${escapeHtml(fmtUntil(o.valid_until))}` : "") + `</span>` +
    `<button class="ghost wd-btn" title="Remove this offer from the market (cannot be undone; re-create to re-post)">Withdraw</button></div>`
  ).join("");
  list.querySelectorAll(".wd-btn").forEach((b) =>
    b.addEventListener("click", () => withdrawOffer(b.closest("[data-id]").dataset.id, b))
  );
}

async function withdrawOffer(id, btn) {
  const msg = $("#my-offers-msg");
  // Withdrawing is outward-facing and easy to hit by accident, so confirm and spell out the effects
  // first (#276).
  if (
    !confirm(
      "Withdraw this offer?\n\n" +
        "• It is removed from the market and peers are told to drop it.\n" +
        "• Any swap already in progress on this offer is unaffected and still completes.\n" +
        "• No funds move.\n" +
        "• You can re-create the offer later.",
    )
  )
    return;
  if (btn) { btn.disabled = true; btn.textContent = "Withdrawing…"; }
  msg.textContent = "";
  try {
    await api("POST", "/offers/" + id + "/withdraw");
    await loadMyOffers();
    loadMarket();
  } catch (e) {
    if (btn) { btn.disabled = false; btn.textContent = "Withdraw"; }
    msg.textContent = "✗ " + ((e.data && e.data.error) || "withdraw failed");
  }
}

// #258: locally dismiss a peer's stale/ghost offer. Local only (no wire message); it cannot come
// back on a relay replay, but it will reappear if the maker genuinely re-announces after this. Only
// clears it from THIS node's market view, so confirm and say so.
async function dismissOffer(id, btn) {
  if (
    !confirm(
      "Dismiss this offer from your market?\n\n" +
        "• It is hidden on this node only; peers are not affected and no funds move.\n" +
        "• It will not come back from a stale relay replay.\n" +
        "• Use this to clear a ghost offer whose maker went silent.",
    )
  )
    return;
  if (btn) { btn.disabled = true; btn.textContent = "Dismissing…"; }
  try {
    await api("POST", "/offers/" + id + "/dismiss");
    loadMarket();
  } catch (e) {
    if (btn) { btn.disabled = false; btn.textContent = "Dismiss"; }
    alert("Dismiss failed: " + ((e.data && e.data.error) || "unknown error"));
  }
}

async function loadMarket() {
  loadMyOffers();
  const [offers, swaps] = await Promise.all([
    api("GET", "/offers").catch(() => []),
    api("GET", "/swaps").catch(() => []),
  ]);
  // #304: hide an offer this node already has an ACTIVE swap on. The maker withdraws a taken offer
  // (design 0250), but relay propagation lags, so a taker filters its own market locally and never
  // re-takes its own in-flight offer. Terminal swaps are NOT filtered: a refunded offer is re-published
  // and legitimately re-takeable, and a done offer has already left the market.
  const engaged = new Set(swaps.filter((s) => !isTerminal(s)).map((s) => s.offer_id));
  const visible = offers.filter((o) => !engaged.has(o.id));
  $("#offers-empty").style.display = visible.length ? "none" : "block";
  mountTable($("#offers"), {
    rows: visible,
    rowId: (o) => o.id,
    defaultSort: 0, // Seen, newest first
    defaultDir: "desc",
    columns: [
      { label: "Seen", get: (o) => o.seen_at || 0, cell: (o) => { const t = fmtTime(o.seen_at); return `<span title="${escapeHtml(t.title)}">${t.text}</span>`; } },
      { label: "Selling", get: (o) => o.sell_chain, cell: (o) => chainTag(o.sell_chain) },
      { label: "Amount", num: true, get: (o) => o.amount_sat, cell: (o) => fmtSats(o.amount_sat) },
      { label: "For", num: true, get: (o) => o.counter_amount_sat, cell: (o) => `${fmtSats(o.counter_amount_sat)} ${chainTag(o.taker_chain)}` },
      { label: "Rate", num: true, get: (o) => o.counter_amount_sat / o.amount_sat, cell: (o) => fmtRate(o.counter_amount_sat / o.amount_sat) },
    ],
    actions: () => `<button class="link take-btn">Take</button> <button class="link dismiss-btn" title="Hide this offer from your market on this node only (for a stale ghost offer)">Dismiss</button> `,
    wireActions: (tr, o) => {
      const b = tr.querySelector(".take-btn");
      if (b) b.addEventListener("click", (e) => { e.stopPropagation(); takeSheet(o); });
      const d = tr.querySelector(".dismiss-btn");
      if (d) d.addEventListener("click", (e) => { e.stopPropagation(); dismissOffer(o.id, d); });
    },
    detailInto: (o, box) => {
      const t = fmtTime(o.seen_at);
      box.innerHTML =
        `<div class="row between"><strong>Offer #${escapeHtml(o.id.slice(0, 8))}</strong>` +
        `<button class="primary take-btn2">Take this offer</button></div>` +
        `<p class="muted">Selling <strong>${fmtSats(o.amount_sat)} ${chainShort(o.sell_chain)}</strong> for ` +
        `<strong>${fmtSats(o.counter_amount_sat)} ${chainShort(o.taker_chain)}</strong> · rate ${fmtRate(o.counter_amount_sat / o.amount_sat)} · seen ${t.text}</p>` +
        `<p class="muted">Lock windows: maker ${o.maker_lock_blocks} blk, taker ${o.taker_lock_blocks} blk · smallest take ${fmtSats(o.min_amount_sat)}.</p>`;
      const b = box.querySelector(".take-btn2");
      if (b) b.addEventListener("click", () => takeSheet(o));
    },
  });
}

// #292: whether the leg THIS node will fund on `chain` is output-only (interactive, no descriptor).
// From /status.funding; the daemon never exposes the descriptor, only this derived flag. An output-only
// leg cannot be signed by opening the PSBT in Sparrow/Shrike, so warn before the user commits to it.
function fundingOutputOnly(chain) {
  const f = statusData && statusData.funding && statusData.funding[chain];
  return !!(f && f.output_only);
}
// #295: the funding wallet's spendable balance for `chain`, or null (output-only / engine down).
function fundingBalanceSat(chain) {
  const f = statusData && statusData.funding && statusData.funding[chain];
  return f && typeof f.balance_sat === "number" ? f.balance_sat : null;
}
// #312: the funding-view replay pre-check, cached per chain for the open sheet. The survey (one
// gettxout per funding UTXO on the other chain) depends only on the wallet, not the leg amount, so we
// fetch it once per chain and compare to the amount on each recompute. `replayWarnCtx` is the leg the
// warning is currently rendered for, so an async survey that lands late only paints the right leg.
const replaySurvey = {}; // chain -> survey | "loading" | {error:true}
let replayWarnCtx = { chain: null, amount: 0 };

// Update the funding preflight warning (#f-fund-warn placeholder) for the leg funded on `chain`,
// locking `amountSat` (0/undefined while the amount is still being typed).
function updateFundWarn(chain, amountSat) {
  const el = $("#f-fund-warn");
  if (!el) return;
  if (fundingOutputOnly(chain)) {
    el.className = "warn";
    el.innerHTML =
      `<strong>Heads up:</strong> your ${chainShort(chain)} leg is set to <strong>output-only</strong> ` +
      `funding (advanced). You fund it by paying exact outputs from a wallet that can build a template, ` +
      `not by signing in Sparrow/Shrike. For the normal sign-in-your-wallet flow, set an account ` +
      `descriptor (descriptor-backed interactive) in Settings.`;
    return;
  }
  if (fundingBalanceSat(chain) === 0) {
    // #295: descriptor-backed but the funding wallet is empty, exactly the configured-but-unsynced
    // state that silently failed at signing time before.
    el.className = "warn";
    el.innerHTML =
      `<strong>Heads up:</strong> your ${chainShort(chain)} funding wallet shows a <strong>0 ` +
      `balance</strong>. It may need a rescan (set a funding birthday in Settings) or a deposit before ` +
      `this leg can fund.`;
    return;
  }
  // Ready to fund: predict the runtime replay guard (#312). Fetch the survey once per chain.
  replayWarnCtx = { chain, amount: amountSat || 0 };
  if (replaySurvey[chain] === undefined) loadReplaySurvey(chain);
  renderReplayWarn(el);
}

async function loadReplaySurvey(chain) {
  replaySurvey[chain] = "loading";
  try {
    replaySurvey[chain] = await api("POST", "/funding/survey", { chain });
  } catch (_) {
    replaySurvey[chain] = { error: true };
  }
  const el = $("#f-fund-warn");
  if (el && replayWarnCtx.chain === chain) renderReplayWarn(el);
}

// Paint the replay warning for the current leg from its cached survey. Warn only when the safe
// (non-replayable) balance cannot cover this leg (coin selection may avoid the replayable coins, so
// "has replayable coins" alone would over-warn); the mode decides whether a split is offered.
function renderReplayWarn(el) {
  const { chain, amount } = replayWarnCtx;
  const d = replaySurvey[chain];
  const clear = () => {
    el.className = "hidden";
    el.innerHTML = "";
  };
  if (!d || d === "loading" || d.output_only) return clear();
  // Fail closed in the UI too: if the coins could not be verified against the other chain, say so,
  // never silently treat them as all-safe. The runtime guard is still the backstop at signing.
  if (d.error || d.unverified) {
    el.className = "warn";
    el.innerHTML =
      `<strong>Heads up:</strong> could not fully verify your ${chainShort(chain)} funding coins ` +
      `against the other chain (node unreachable). The replay guard still refuses any ` +
      `cross-chain-replayable coin when you sign.`;
    return;
  }
  // Warn only when there ARE replayable coins AND the safe (non-replayable) balance cannot cover this
  // leg: coin selection may avoid the replayable coins, so "has replayable coins" alone would
  // over-warn, and too little total balance is the #295 0-balance concern, not a replay problem.
  if (amount && d.replayable_sat > 0 && d.safe_sat < amount) {
    // Whether a split is available depends on the Blake2b funding wallet, not the chain being funded: the
    // split needs a wallet to lend a marker. Hot (keyed) and cold / descriptor-backed (watch-only) both
    // work (#314/#310); only output-only funding has no wallet, so it cannot split.
    const xbtcOutputOnly = !!(statusData && statusData.funding && statusData.funding.xbtc && statusData.funding.xbtc.output_only);
    el.className = "warn";
    const held =
      `Your ${chainShort(chain)} funding wallet holds ${fmtSats(d.replayable_sat)} ${chainShort(chain)} ` +
      `in pre-fork coin(s) that are replayable across chains, and only ${fmtSats(d.safe_sat)} that is ` +
      `safe to lock, less than this leg needs.`;
    if (!xbtcOutputOnly) {
      el.innerHTML =
        `<strong>Split first.</strong> ${held} Separate them in the ` +
        `<a href="#" id="f-go-split">Split</a> tab first, or the swap will be refused when you sign ` +
        `the funding transaction.`;
      const go = $("#f-go-split");
      if (go)
        go.addEventListener("click", (e) => {
          e.preventDefault();
          const tab = document.querySelector('.tab[data-tab="split"]');
          if (tab) tab.click();
        });
    } else {
      el.innerHTML =
        `<strong>Heads up:</strong> ${held} The swap will refuse these coins, and splitting needs a ` +
        `Blake2b funding wallet, which output-only funding does not have, so fund this leg from coins ` +
        `that are already separated.`;
    }
    return;
  }
  clear();
}

function offerForm(o) {
  if (o) {
    // Take: framed from the TAKER's side (#296), the mirror of the maker's offer, so the destination
    // fields read as "receive what you buy" / "refund what you lock" rather than the maker's wording.
    return `<div class="row between"><h2>Take offer</h2>
        <button class="link" id="f-x" title="Close this dialog (changes nothing)">✕</button></div>
      <p class="muted">You pay <strong>${fmtSats(o.counter_amount_sat)} ${chainShort(o.taker_chain)}</strong>
        and receive <strong>${fmtSats(o.amount_sat)} ${chainShort(o.sell_chain)}</strong> ·
        rate ${fmtRate(o.counter_amount_sat / o.amount_sat)}.</p>
      <div class="warn"><strong>Non-custodial.</strong> Your keys never leave your node; a swap ends claimed or refunded.</div>
      <details style="margin:.4rem 0"><summary class="muted">Send this trade's coins to a specific address (optional)</summary>
        <label title="Where you receive the ${chainShort(o.sell_chain)} you are buying. Leave blank to use your configured payout, or a fresh address from your node wallet.">
          Receive your ${chainTag(o.sell_chain)} at <input id="f-claim-dest" placeholder="blank = your configured payout"></label>
        <label title="Where your own ${chainShort(o.taker_chain)} refunds if this swap stalls. Leave blank to use your configured payout.">
          Refund your ${chainTag(o.taker_chain)} to <input id="f-refund-dest" placeholder="blank = your configured payout"></label>
      </details>
      <div class="hidden" id="f-fund-warn"></div>
      <div class="row between">
        <button class="ghost" id="f-cancel" title="Close this dialog (does not withdraw an offer or cancel a swap)">Close</button>
        <button class="primary" id="f-go">Take</button>
      </div>
      <p id="f-msg" class="muted"></p>`;
  }
  // Create: market-anchored pricing (design 0025). The nonkyc rate is the default and anchor; you add a
  // whole-percent maker margin. The rate is not something you invent.
  return `<div class="row between"><h2>Create offer</h2>
      <button class="link" id="f-x" title="Close this dialog (changes nothing)">✕</button></div>
    <label>I am selling
      <select id="f-chain">
        <option value="xbtc">${chainShort("xbtc")}</option>
        <option value="btc">${chainShort("btc")}</option>
      </select></label>
    <label>Amount (<span id="f-sell-coin">${chainShort("xbtc")}</span>) <input id="f-amount" placeholder="0.5"></label>
    <p id="f-market" class="muted">Loading the market rate…</p>
    <label title="Your margin off the nonkyc market rate, in whole percent (1% steps). Positive earns you more as the maker; negative undercuts the market to fill faster. The rate comes from nonkyc; you choose only the margin.">
      Your maker margin (%) <input id="f-margin" type="number" step="1" value="0"></label>
    <label title="What the taker pays you for the whole amount, priced from the nonkyc rate and your margin. Computed from the market, not editable.">
      You receive (<span id="f-recv-coin">${chainShort("btc")}</span>) <input id="f-recv" readonly></label>
    <details style="margin:.4rem 0"><summary class="muted">Send this offer's coins to a specific address (optional)</summary>
      <label title="Where the coin you receive from this swap is sent. Leave blank to use your configured payout, or a fresh address from your node wallet.">
        Claim destination (<span id="f-claim-coin">${chainShort("btc")}</span>) <input id="f-claim-dest" placeholder="blank = your configured payout"></label>
      <label title="Where your own coin refunds if the swap stalls. Leave blank to use your configured payout.">
        Refund destination (<span id="f-refund-coin">${chainShort("xbtc")}</span>) <input id="f-refund-dest" placeholder="blank = your configured payout"></label>
    </details>
    <p id="f-eff" class="muted"></p>
    <label title="How many days the offer stays valid. After this it is dropped from the market and can no longer be taken. Leave blank for no explicit expiry (it still ages out if you stop re-announcing).">
      Valid for (days, optional) <input id="f-days" type="number" min="1" step="1" placeholder="no expiry"></label>
    <div id="f-d6" class="warn hidden"></div>
    <div class="hidden" id="f-fund-warn"></div>
    <div class="warn"><strong>Non-custodial.</strong> Your keys never leave your node; a swap ends claimed or refunded.</div>
    <div class="row between">
      <button class="ghost" id="f-cancel" title="Close this dialog (does not withdraw an offer or cancel a swap)">Close</button>
      <button class="primary" id="f-go">Publish offer</button>
    </div>
    <p id="f-msg" class="muted"></p>`;
}

function openSheet(html) {
  $("#modal .sheet").innerHTML = html;
  $("#modal").classList.remove("hidden");
  const close = () => $("#modal").classList.add("hidden");
  $("#f-cancel").onclick = close;
  const x = $("#f-x");
  if (x) x.onclick = close;
}

function createSheet() {
  // #253: refuse at the handler too, not only by disabling the button, since the status may change.
  const h = health();
  if (!h.trade) { alert("Create offer is unavailable right now: " + h.reason + "."); return; }
  // #312: survey the funding wallet afresh for this sheet (so a just-finished split is not stale).
  for (const k in replaySurvey) delete replaySurvey[k];
  openSheet(offerForm(null));
  let ref = null; // { rate: BTC per xBTC, band: price_band_pct, verify } or null when unavailable
  let refLoaded = false; // whether the first /reference-rate fetch has returned yet (#263)
  let refVerify = ""; // #254: the nonkyc verify URL, kept even when the rate is unavailable, for a link
  const go = $("#f-go");

  // The market price (counter coin per unit of the sold coin) for the current direction.
  const marketPrice = () =>
    !ref ? null : $("#f-chain").value === "xbtc" ? ref.rate : 1 / ref.rate;

  async function loadReference() {
    try {
      // #254: force a live fetch (not the header's cached poll) so opening the form and the Refresh
      // button read the current rate and a Refresh after a failure actually retries.
      const r = await api("GET", "/reference-rate?fresh=1");
      refVerify = r && r.verify_url ? r.verify_url : refVerify;
      ref =
        r.enabled && !r.error && isFinite(r.rate) && r.rate > 0
          ? { rate: r.rate, band: Number.isFinite(r.price_band_pct) ? r.price_band_pct : 10, verify: r.verify_url }
          : null;
    } catch (e) {
      ref = null;
    }
    refLoaded = true;
    recompute();
  }

  function recompute() {
    const market = $("#f-market"), eff = $("#f-eff"), d6 = $("#f-d6"), recv = $("#f-recv");
    const sell = $("#f-chain").value, taker = sell === "xbtc" ? "btc" : "xbtc";
    // Keep the leg labels in step with the direction.
    $("#f-sell-coin").textContent = chainShort(sell);
    $("#f-recv-coin").textContent = chainShort(taker);
    // #257: claim is on the chain you receive, refund on the chain you lock (sell).
    const cc = $("#f-claim-coin"), rc = $("#f-refund-coin");
    if (cc) cc.textContent = chainShort(taker);
    if (rc) rc.textContent = chainShort(sell);
    // #292: the maker funds (locks) the chain it sells; warn if that leg is output-only.
    // #312: and whether its coins are cross-chain-replayable (split-first) for the amount being sold.
    updateFundWarn(sell, parseBtc($("#f-amount").value));
    const amount = parseBtc($("#f-amount").value);
    if (!ref) {
      // No market-derived price. The form prices only from the market, so it cannot publish until the
      // reference is back.
      market.textContent = "";
      recv.value = "";
      go.disabled = true;
      if (!refLoaded) {
        // The first fetch can be a slow Tor round-trip; don't flash the "unavailable" warning while it
        // is still in flight (#263).
        d6.classList.add("hidden");
        eff.textContent = "Checking the market rate…";
        return;
      }
      eff.textContent = "";
      d6.classList.remove("hidden");
      // #254: a clickable fallback to read the rate at the source, plus a Refresh that re-fetches live.
      const link = refVerify
        ? ` <a href="${escapeHtml(refVerify)}" target="_blank" rel="noopener noreferrer">Check the rate at nonkyc</a>.`
        : "";
      d6.innerHTML =
        "<strong>Market rate unavailable.</strong> The nonkyc reference is off or unreachable, so an offer cannot be priced from the market. Enable the price reference, then " +
        `<button type="button" id="f-refresh" class="link">refresh</button>.${link}`;
      const rf = $("#f-refresh");
      if (rf) rf.onclick = () => loadReference();
      return;
    }
    d6.classList.add("hidden");
    const verify = ref.verify
      ? ` · <a href="${escapeHtml(ref.verify)}" target="_blank" rel="noopener noreferrer">verify</a>`
      : "";
    market.innerHTML =
      `Market (nonkyc): 1 ${chainShort("btc")} = <strong>${(1 / ref.rate).toFixed(2)}</strong> ${chainShort("xbtc")} · ` +
      `1 ${chainShort("xbtc")} = <strong>${ref.rate.toFixed(8)}</strong> ${chainShort("btc")}${verify}. Band ±${ref.band}%.`;
    const mp = marketPrice();
    const margin = parseInt($("#f-margin").value, 10) || 0;
    const overBand = Math.abs(margin) > ref.band;
    go.disabled = overBand;
    const profit = margin > 0
      ? `you ask ${margin}% above market (earn more; may fill slower)`
      : margin < 0
        ? `you undercut market by ${-margin}% (fill faster; earn less)`
        : "exactly the market rate";
    if (overBand) {
      recv.value = "";
      eff.innerHTML = `<span style="color:var(--orange)">⚠ ${margin}% exceeds the ±${ref.band}% band; lower the margin.</span>`;
      return;
    }
    // Market-derived: price = market * (1 + margin/100); the daemon finalizes the counter at publish.
    const price = mp * (1 + margin / 100);
    recv.value = amount ? fmtSats(Math.ceil(amount * price)) : "";
    eff.innerHTML = `Rate ${fmtRate(price)} (${margin >= 0 ? "+" : ""}${margin}% vs market), ${profit}.`;
  }

  $("#f-chain").onchange = recompute;
  $("#f-amount").addEventListener("input", recompute);
  $("#f-margin").addEventListener("input", recompute);
  loadReference();

  go.onclick = async () => {
    const amount = parseBtc($("#f-amount").value);
    if (amount === null) return ($("#f-msg").textContent = "Enter a valid amount.");
    // Always the market-derived path: send only the whole-percent margin; the daemon prices it off the
    // live reference, so the published rate is the market rate at publish time, always in band.
    const sellChain = $("#f-chain").value;
    if (
      fundingOutputOnly(sellChain) &&
      !confirm(
        `Your ${chainShort(sellChain)} leg is output-only funding (advanced): you fund it by paying exact ` +
          `outputs from your own wallet, not by signing in Sparrow/Shrike. Publish this offer anyway?`,
      )
    )
      return;
    const body = {
      sell_chain: sellChain,
      amount_sat: amount,
      min_amount_sat: amount,
      margin_pct: parseInt($("#f-margin").value, 10) || 0,
    };
    const days = parseInt($("#f-days").value, 10);
    if (Number.isFinite(days) && days > 0) body.valid_days = days;
    // #257: optional per-trade destinations (blank falls back to the configured payout).
    const cd = ($("#f-claim-dest") || {}).value, rd = ($("#f-refund-dest") || {}).value;
    if (cd && cd.trim()) body.claim_dest = cd.trim();
    if (rd && rd.trim()) body.refund_dest = rd.trim();
    try {
      await api("POST", "/offers", body);
      $("#modal").classList.add("hidden");
      loadMarket();
    } catch (e) {
      $("#f-msg").textContent = (e.data && (e.data.error || (e.data.fields || []).join("; "))) || "rejected";
    }
  };
}

function takeSheet(o) {
  const h = health();
  if (!h.trade) { alert("Taking an offer is unavailable right now: " + h.reason + "."); return; }
  // #312: survey the funding wallet afresh for this sheet (so a just-finished split is not stale).
  for (const k in replaySurvey) delete replaySurvey[k];
  openSheet(offerForm(o));
  // #292: the taker funds its own lock on the taker chain; warn if that leg is output-only.
  // #312: the taker locks counter_amount_sat on the taker chain; flag replayable funding coins for it.
  updateFundWarn(o.taker_chain, o.counter_amount_sat);
  $("#f-go").onclick = async () => {
    if (
      fundingOutputOnly(o.taker_chain) &&
      !confirm(
        `Your ${chainShort(o.taker_chain)} leg is output-only funding (advanced): you fund it by paying ` +
          `exact outputs from your own wallet, not by signing in Sparrow/Shrike. Take this offer anyway?`,
      )
    )
      return;
    try {
      // #257: optional per-trade destinations (blank falls back to the configured payout).
      const tb = { amount_sat: o.amount_sat };
      const cd = ($("#f-claim-dest") || {}).value, rd = ($("#f-refund-dest") || {}).value;
      if (cd && cd.trim()) tb.claim_dest = cd.trim();
      if (rd && rd.trim()) tb.refund_dest = rd.trim();
      const r = await api("POST", `/offers/${o.id}/take`, tb);
      $("#modal").classList.add("hidden");
      $$(".tab").find((t) => t.dataset.tab === "swaps").click();
      void r;
    } catch (e) {
      $("#f-msg").textContent = (e.data && e.data.error) || "rejected";
    }
  };
}
$("#new-offer").onclick = createSheet;

// Donation sheet (footer). Both addresses are already public on the TwentyOne.Life profile. They
// share Bitcoin's address format but are DIFFERENT assets on different networks, so each is labelled
// and the caveat is explicit: coins sent to the wrong network do not arrive as the intended asset.
function donateSheet() {
  // Silent payment (BIP352): one published address for both chains. Each donation lands on a fresh,
  // unlinkable taproot output the sender derives, so nothing clusters to this address. Receiving needs
  // only scanning on our side (no BIP352-aware signer), unlike the swap fee we pay out.
  const sp = "sp1qq25802j9uk3t2yvthqmpxhp7pjus8rrvxyvlw27445qwhu3agd0kuqnqpct3v645d8x058tas4p83em7qdam8dr6t0ntecf2n00ywet7xc682jk7";
  // Standard-address fallback for wallets that cannot send to a silent-payment address: the project's
  // published per-chain donation addresses.
  const fallback = [
    { chain: "btc", addr: "bc1qzz077zqg9e0ymy7euhrmfyfmsfuqggtlr7v9mf" },
    { chain: "xbtc", addr: "bc1ql66ssq24t7w4jl8updfrs820efnujp0m5jjuqk" },
  ];
  const fb = fallback.map((a) =>
    `<label>${chainLink(a.chain)} <span class="muted">(${escapeHtml(chainNote(a.chain))})</span>` +
    `<input readonly class="copyable" value="${escapeHtml(a.addr)}"></label>`,
  ).join("");
  return (
    `<div class="row between"><strong>Donate to TwentyOne.Life</strong>` +
    `<button class="link" id="f-x" title="Close">✕</button></div>` +
    `<p class="muted"><strong>Silent payment (recommended).</strong> One address for both ${chainShort("btc")} and ${chainShort("xbtc")}. ` +
    `Each donation lands on a fresh, unlinkable address, so nothing clusters to this one. It settles on ` +
    `whichever chain you send from. Needs a wallet that supports silent payments (BIP352).</p>` +
    `<label>Silent payment (${chainShort("btc")} or ${chainShort("xbtc")})` +
    `<input readonly class="copyable" value="${escapeHtml(sp)}"></label>` +
    `<p class="muted">Or a standard address, if your wallet cannot send to a silent-payment one. These ` +
    `two share Bitcoin's address format but are different assets on different networks: send only the ` +
    `matching coin to each, or it will not arrive as intended.</p>${fb}` +
    `<div class="row" style="justify-content:flex-end"><button class="ghost" id="f-cancel">Close</button></div>`
  );
}
const donateBtn = $("#donate");
if (donateBtn) donateBtn.onclick = () => openSheet(donateSheet());

// --- swaps ---
let lastSwaps = [];
async function loadSwaps() {
  // Live swaps only; terminal ones belong in History (they would otherwise show in both tabs).
  const all = await api("GET", "/swaps").catch(() => []);
  lastSwaps = all.filter((s) => !isTerminal(s));
  $("#swaps-empty").style.display = lastSwaps.length ? "none" : "block";
  mountTable($("#swaps-table"), {
    rows: lastSwaps,
    rowId: (s) => s.id,
    defaultSort: 0, // Started, newest first
    defaultDir: "desc",
    columns: [
      { label: "Started", get: (s) => s.started_at || 0, cell: (s) => { const t = fmtTime(s.started_at); return `<span title="${escapeHtml(t.title)}">${t.text}</span>`; } },
      { label: "Swap", get: (s) => s.id, cell: (s) => "#" + s.id.slice(0, 6) },
      { label: "Role", get: (s) => s.role, cell: (s) => s.role },
      { label: "Direction", get: (s) => s.maker_chain, cell: (s) => `${chainTag(s.maker_chain)}→${chainTag(s.taker_chain)}` },
      { label: "Phase", get: (s) => s.phase, cell: (s) => { const cls = isTerminal(s) ? "phase-" + s.phase : "phase-active"; return `<span class="pill ${cls}">${s.phase}</span>`; } },
    ],
    detailInto: (s, box) => fillSwapDetail(s.id, box),
  });
}

// A bare txid rendered as a link to the operator's configured per-chain explorer (#67/#32), or the
// shortened txid as plain text when no explorer URL is set. The explorer base comes from /status
// (btc_explorer_url / xbtc_explorer_url); the default on StartOS is the operator's own mempool.
function explorerLink(chain, txid) {
  if (!txid) return "-";
  const base = chain === "btc" ? statusData?.btc_explorer_url : statusData?.xbtc_explorer_url;
  const short = String(txid).slice(0, 16) + "…";
  return base
    ? `<a href="${escapeHtml(base.replace(/\/$/, ""))}/tx/${escapeHtml(txid)}" target="_blank" rel="noopener">${escapeHtml(short)}</a>`
    : short;
}

// A lock (txid + confirmation state) rendered for the live per-swap detail. Confirmations show as
// count/required when the daemon reports the required depth (#268), and the state is coloured by
// progress: muted before it is locked, orange while confirming, green once settled or spent (#267).
function explorerTx(chain, lock) {
  if (!lock || !lock.txid)
    return `<span style="color:var(--dim)">not locked yet</span>`;
  const need = lock.required_depth;
  const confs = lock.confirmations;
  // #303: once the required depth is met the leg is done, so clamp the numerator at `need` rather than
  // keep counting (`2/1`, `3/1`), which reads like "2 of 1" / partial instead of "met, 1 required".
  const count =
    confs == null
      ? "unconfirmed"
      : need
        ? `${Math.min(confs, need)}/${need} conf`
        : `${confs} conf`;
  const lockSettled = confs != null && (!need || confs >= need);
  // #307: once the lock is spent, show the SPEND (claim or refund) confirming, not a bare "spent", so the
  // long `claiming -> done` wait has a countdown. The swap is done when a claim is required_depth deep.
  let state, color;
  if (lock.spend) {
    const sp = lock.spend;
    const sneed = sp.required_depth;
    const sconf = sp.confirmations ?? 0;
    const sdone = sneed ? sconf >= sneed : sconf > 0;
    const scount = sneed ? `${Math.min(sconf, sneed)}/${sneed} conf` : `${sconf} conf`;
    state = `${sp.is_claim ? "claim" : "refund"} ${scount}${sdone ? " · done" : ""}`;
    color = sdone ? "var(--ok)" : "var(--orange)";
  } else {
    state = count + " · locked";
    color = lockSettled ? "var(--ok)" : confs == null ? "var(--dim)" : "var(--orange)";
  }
  // #309: the required depth the engine enforces is a value-based security FLOOR (deeper for larger
  // swaps), which can exceed the configured btc_conf/xbtc_conf; label it so a user who set 2 and sees 6
  // understands why. The setting raises this floor, never lowers it.
  const depthTitle = need
    ? `Requires ${need} confirmation(s): a value-based security floor for this amount (low-hashrate reorg safety). Your btc_conf/xbtc_conf can raise this, never lower it below the floor.`
    : "";
  return `${explorerLink(chain, lock.txid)}<br><span style="color:${color}" title="${escapeHtml(depthTitle)}">${escapeHtml(state)}</span>`;
}

// #307: a compact step breadcrumb over the swap lifecycle, current step highlighted, so the long
// `locking` and `claiming` waits read as "you are here" rather than one static phase word. Derived
// from the daemon phase plus the own-lock state, phrased the same for maker and taker. Refund is the
// alternate terminal branch.
function swapStepper(s, ownLock) {
  const p = s.phase;
  const refund = p === "refunding" || p === "refunded";
  const steps = refund
    ? ["Taken", "Locked", "Refunding", "Refunded"]
    : ["Taken", "Fund lock", "Locked", "Claiming", "Done"];
  let cur;
  if (refund) cur = p === "refunded" ? 3 : 2;
  else if (p === "done") cur = 4;
  else if (p === "claiming") cur = 3;
  else cur = ownLock && (ownLock.spent || ownLock.confirmations != null) ? 2 : 1; // locking
  const sep = `<span style="color:var(--dim)"> → </span>`;
  return (
    `<div style="margin:.2rem 0;font-size:.85em">` +
    steps
      .map((label, i) => {
        const color = i < cur ? "var(--ok)" : i === cur ? "var(--orange)" : "var(--dim)";
        const mark = i < cur ? "✓ " : i === cur ? "▸ " : "";
        return `<span style="color:${color}">${mark}${escapeHtml(label)}</span>`;
      })
      .join(sep) +
    `</div>`
  );
}

// History / ledger (#67): the daemon derives per-swap entries + totals from its own records at
// GET /history; this view only renders them. Each entry already carries the realized rate and the
// voluntary fee paid, so the detail needs no extra fetch (unlike the live Swaps detail).
async function loadHistory() {
  const h = await api("GET", "/history").catch(() => null);
  // The ledger lists only terminal swaps; any still in flight show in the Swaps tab (and are counted
  // as "in flight" in the totals line below).
  // Unified ledger (#218): terminal swaps plus completed splits in one table. A split row carries
  // kind:"split"; swap rows have no kind.
  const swapRows = ((h && h.swaps) || []).filter(isTerminal);
  const splitRows = ((h && h.splits) || []).map((s) => ({ ...s, kind: "split" }));
  const entries = swapRows.concat(splitRows);
  const isSplit = (r) => r && r.kind === "split";
  const t = h && h.totals;
  $("#history-empty").style.display = entries.length ? "none" : "block";
  $("#history-totals").innerHTML = t
    ? `${t.count} swap(s) · ${t.done} done · ${t.refunded} refunded · ${t.abandoned} abandoned` +
      (t.active ? ` · ${t.active} in flight` : "") +
      (splitRows.length ? ` · ${splitRows.length} split(s)` : "") +
      ` · volume ${fmtSats(t.volume_sat.btc)} ${chainShort("btc")} / ${fmtSats(t.volume_sat.xbtc)} ${chainShort("xbtc")}` +
      ` · voluntary fee paid ${fmtSats(t.voluntary_fee_paid.total_sat)} over ${t.voluntary_fee_paid.swaps} swap(s)`
    : "";
  mountTable($("#history-table"), {
    rows: entries,
    rowId: (s) => (isSplit(s) ? "split-" + s.txid : s.id),
    defaultSort: 0, // Started, newest first
    defaultDir: "desc",
    columns: [
      { label: "Started", get: (s) => (isSplit(s) ? s.time : s.started_at) || 0, cell: (s) => { const tt = fmtTime(isSplit(s) ? s.time : s.started_at); return `<span title="${escapeHtml(tt.title)}">${tt.text}</span>`; } },
      { label: "Ref", get: (s) => (isSplit(s) ? s.txid : s.id), cell: (s) => "#" + String(isSplit(s) ? s.txid : s.id).slice(0, 6) },
      { label: "Role", get: (s) => (isSplit(s) ? "split" : s.role), cell: (s) => (isSplit(s) ? "split" : s.role) },
      { label: "Direction", get: (s) => (isSplit(s) ? "split" : s.maker_chain), cell: (s) => (isSplit(s) ? `protect ${fmtSats(s.protected_sat)} ${chainTag("xbtc")}` : `${chainTag(s.maker_chain)}→${chainTag(s.taker_chain)}`) },
      { label: "Rate", num: true, get: (s) => (isSplit(s) ? 0 : s.rate || 0), cell: (s) => (isSplit(s) ? "-" : fmtRate(s.rate)) },
      { label: "Fee paid", num: true, get: (s) => (isSplit(s) ? s.fee_sat || 0 : s.voluntary_fee_paid_sat || 0), cell: (s) => (isSplit(s) ? fmtSats(s.fee_sat) : s.voluntary_fee_paid_sat == null ? "-" : fmtSats(s.voluntary_fee_paid_sat)) },
      { label: "Phase", get: (s) => (isSplit(s) ? "split" : s.phase), cell: (s) => { if (isSplit(s)) return `<span class="pill phase-done">split</span>`; const cls = isTerminal(s) ? "phase-" + s.phase : "phase-active"; return `<span class="pill ${cls}">${s.phase}</span>`; } },
    ],
    detailInto: (s, box) => {
      if (isSplit(s)) {
        box.innerHTML =
          `<p class="muted">Coin split · protected ${fmtSats(s.protected_sat)} ${chainShort("xbtc")} · fee ${fmtSats(s.fee_sat)} ${chainShort("xbtc")}</p>` +
          `<p class="muted">Separating tx (${chainShort("xbtc")}): ${explorerLink("xbtc", s.txid)}</p>` +
          (s.inputs && s.inputs.length ? `<p class="muted">Protected coin(s): ${s.inputs.map(escapeHtml).join(", ")}</p>` : "") +
          (s.dest ? `<p class="muted">Sent to: ${escapeHtml(s.dest)}</p>` : "");
        return;
      }
      const ownChain = s.role === "maker" ? s.maker_chain : s.taker_chain;
      // #251: a completed swap reads as a "done deal" linked back to the offer it filled.
      const dealHead =
        s.phase === "done"
          ? `<p><strong>✓ Done deal</strong>${s.offer_id ? ` from offer #${escapeHtml(String(s.offer_id).slice(0, 6))}` : ""}</p>`
          : "";
      box.innerHTML =
        dealHead +
        `<p class="muted">${s.role} · ${fmtSats(s.maker_amount_sat)} ${chainShort(s.maker_chain)} for ` +
        `${fmtSats(s.taker_amount_sat)} ${chainShort(s.taker_chain)} · realized rate ${fmtRate(s.rate)}` +
        (s.secret_revealed ? " · secret revealed" : "") + `</p>` +
        `<p class="muted">Voluntary fee paid: ${s.voluntary_fee_paid_sat == null ? "none" : fmtSats(s.voluntary_fee_paid_sat) + " " + chainShort(ownChain)}</p>` +
        `<p class="muted">Your lock (${chainShort(ownChain)}): ${explorerLink(ownChain, s.our_lock_txid)}</p>` +
        `<p class="muted">The counterparty leg's txids are on the live Swaps view while a swap is in flight.</p>`;
    },
  });
}

// Per-swap draft of the pasted signed PSBT, held outside the DOM so no refresh of the detail panel
// can wipe what the user is typing/pasting (#265). Cleared on a successful submit.
const psbtDrafts = {};

// #274: animated UR (ur:crypto-psbt) QR of the unsigned funding PSBT, for air-gapped signers. State
// lives outside the DOM because the detail panel re-renders on every poll: `qrParts` caches the parts
// per swap (so we don't refetch each poll), `qrShown` remembers whether the user opened the QR (so it
// is re-attached after a rebuild), and a single `qrTimer` drives the frame animation.
const qrParts = {}; // id -> { psbt, parts }: keyed by PSBT content so a re-parked PSBT is never stale
const qrShown = {};
let qrTimer = null;
let qrFrame = 0;

function stopQrAnim() {
  if (qrTimer) {
    clearInterval(qrTimer);
    qrTimer = null;
  }
}

// Draw one UR part string as a QR on `canvas`, alphanumeric mode (the parts are upper-case + ":/-", in
// the QR alphanumeric set, so the code stays low-version). Returns false if it could not be encoded.
function drawQr(canvas, text) {
  try {
    const qr = qrcode(0, "M"); // auto version, medium error correction
    qr.addData(text, "Alphanumeric");
    qr.make();
    const n = qr.getModuleCount();
    const ctx = canvas.getContext("2d");
    const quiet = 2;
    const cell = Math.floor(canvas.width / (n + quiet * 2));
    const off = Math.floor((canvas.width - cell * (n + quiet * 2)) / 2) + quiet * cell;
    ctx.fillStyle = "#fff";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = "#000";
    for (let r = 0; r < n; r++)
      for (let c = 0; c < n; c++)
        if (qr.isDark(r, c)) ctx.fillRect(off + c * cell, off + r * cell, cell, cell);
    return true;
  } catch (_) {
    return false;
  }
}

// Attach the animation to the current #qr-canvas for swap `id` (the element is recreated on each
// re-render). Self-stops when that canvas leaves the document, so a closed/rebuilt panel leaves no
// timer running.
function startQrAnim(id) {
  stopQrAnim();
  const parts = qrParts[id] && qrParts[id].parts;
  const box = $("#qr-box");
  const canvas = $("#qr-canvas");
  const label = $("#qr-label");
  if (!parts || !parts.length || !box || !canvas) return;
  box.classList.remove("hidden");
  qrFrame = qrFrame % parts.length;
  const paint = () => {
    if (!document.body.contains(canvas)) return stopQrAnim();
    const ok = drawQr(canvas, parts[qrFrame]);
    if (label)
      label.textContent = ok
        ? parts.length > 1
          ? `Frame ${qrFrame + 1} / ${parts.length} · scan the whole loop (SeedSigner, Coldcard Q)`
          : "Scan with your air-gapped signer (SeedSigner, Coldcard Q)"
        : "This PSBT is too large to show as a QR; use Copy instead.";
    qrFrame = (qrFrame + 1) % parts.length;
  };
  paint();
  if (parts.length > 1) qrTimer = setInterval(paint, 600);
}

// #274 PR2: scan a signed PSBT back from an air-gapped signer's animated ur:crypto-psbt QR, via the
// camera (getUserMedia) or an uploaded image. Each decoded frame is a UR fragment; the growing set is
// POSTed to the daemon's /psbt/from-ur, which fountain-reassembles them. On completion `onPsbt(base64)`
// fires. jsQR (vendored, verified) does the per-frame QR decode; the daemon does the UR decode.
async function startPsbtScan(onPsbt) {
  const ov = document.createElement("div");
  ov.style.cssText =
    "position:fixed;inset:0;background:rgba(0,0,0,.88);z-index:1000;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:12px;padding:16px";
  ov.innerHTML =
    `<div style="color:#ddd;font-size:15px">Scan the signer's animated QR (SeedSigner, Sparrow, Shrike)</div>` +
    `<video id="scan-video" playsinline muted style="max-width:92vw;max-height:58vh;border-radius:8px;background:#000"></video>` +
    `<canvas id="scan-canvas" style="display:none"></canvas>` +
    `<div id="scan-status" style="color:var(--orange);font-size:14px">starting camera…</div>` +
    `<div style="display:flex;gap:12px;align-items:center">` +
    `<label class="link" style="color:#ddd;cursor:pointer">Use an image instead<input id="scan-file" type="file" accept="image/*" style="display:none"></label>` +
    `<button id="scan-close" class="ghost" type="button">Cancel</button></div>`;
  document.body.appendChild(ov);
  const video = ov.querySelector("#scan-video");
  const canvas = ov.querySelector("#scan-canvas");
  const status = ov.querySelector("#scan-status");
  const parts = new Set();
  let stream = null,
    raf = null,
    done = false,
    posting = false,
    lastScan = 0;
  const cleanup = () => {
    done = true;
    if (raf) cancelAnimationFrame(raf);
    if (stream) stream.getTracks().forEach((t) => t.stop());
    ov.remove();
  };
  ov.querySelector("#scan-close").onclick = cleanup;

  // Decode one frame's QR; collect UR parts; ask the daemon to reassemble. One POST in flight at a time.
  const onImage = async (data, w, h) => {
    if (done || typeof jsQR !== "function") return;
    const code = jsQR(data, w, h);
    if (!code || !code.data) return;
    const str = code.data.trim();
    if (!/^ur:crypto-psbt\//i.test(str)) {
      status.textContent = "that QR is not a ur:crypto-psbt PSBT";
      return;
    }
    if (parts.has(str) || posting) return;
    parts.add(str);
    status.textContent = `read ${parts.size} frame(s)…`;
    posting = true;
    try {
      const r = await api("POST", "/psbt/from-ur", { parts: [...parts] });
      if (r.complete && r.psbt) {
        cleanup();
        onPsbt(r.psbt);
      }
    } catch (e) {
      status.textContent = "✗ " + ((e.data && e.data.error) || "decode failed");
    } finally {
      posting = false;
    }
  };

  ov.querySelector("#scan-file").onchange = (e) => {
    const f = e.target.files && e.target.files[0];
    if (!f) return;
    // A data: URL, not a blob: one, so the <img> load satisfies the GUI's `img-src 'self' data:` CSP.
    const reader = new FileReader();
    reader.onload = () => {
      const img = new Image();
      img.onload = () => {
        canvas.width = img.width;
        canvas.height = img.height;
        const ctx = canvas.getContext("2d");
        ctx.drawImage(img, 0, 0);
        const d = ctx.getImageData(0, 0, canvas.width, canvas.height);
        onImage(d.data, d.width, d.height);
      };
      img.src = reader.result;
    };
    reader.readAsDataURL(f);
  };

  try {
    stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
    video.srcObject = stream;
    await video.play();
    status.textContent = "point at the animated QR…";
    const ctx = canvas.getContext("2d");
    const loop = (ts) => {
      if (done) return;
      // Throttle the decode to ~6/s: full-frame QR decode is CPU-heavy, and signers animate slowly.
      if (video.readyState >= 2 && ts - lastScan > 160) {
        lastScan = ts;
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
        const d = ctx.getImageData(0, 0, canvas.width, canvas.height);
        onImage(d.data, d.width, d.height);
      }
      raf = requestAnimationFrame(loop);
    };
    raf = requestAnimationFrame(loop);
  } catch (_e) {
    status.textContent = "camera unavailable (allow access, or use an image instead)";
  }
}

async function fillSwapDetail(id, box) {
  // Only show the placeholder on first open; on a refresh keep the current content so the panel does
  // not flash or tear down the signing inputs (#265).
  if (!box.querySelector("[data-sd]")) box.innerHTML = `<span class="muted">Loading…</span>`;
  const s = await api("GET", "/swaps/" + id).catch(() => null);
  const st = $("#swaps-table")._v;
  if (!st || st.open !== id) return; // row closed or changed during the fetch
  const live = $("#swaps-table").querySelector(".detail-box");
  if (!live) return;
  // The panel is about to be rebuilt; stop any QR animation bound to the old (detaching) canvas (#274).
  stopQrAnim();
  if (!s) { live.innerHTML = `<span class="muted">detail unavailable</span>`; return; }
  const c = s.chain || {};
  // Our own lock is on our side of the swap, which is the taker lock when we are the taker (#73).
  const ownChain = s.role === "maker" ? s.maker_chain : s.taker_chain;
  const cpChain = s.role === "maker" ? s.taker_chain : s.maker_chain;
  const ownLock = s.role === "maker" ? c.maker_lock : c.taker_lock;
  const cpLock = s.role === "maker" ? c.taker_lock : c.maker_lock;
  live.innerHTML =
    // #306: the authoritative phase, rendered from the detail's own fresh `/swaps/{id}` fetch so it
    // tracks the daemon every poll (the row badge above can lag while a detail is open). Both roles.
    `<p data-sd style="margin:.2rem 0"><span class="pill ${isTerminal(s) ? "phase-" + s.phase : "phase-active"}" title="Swap phase, from the daemon each poll">${escapeHtml(s.phase)}</span>` +
    `<span class="muted"> · ${s.role} · ${fmtSats(s.maker_amount_sat)} ${chainShort(s.maker_chain)} for ${fmtSats(s.taker_amount_sat)} ${chainShort(s.taker_chain)}` +
    (s.secret_revealed ? " · secret revealed" : "") + `</span></p>` +
    swapStepper(s, ownLock) +
    `<div class="legs">` +
    `<div class="leg card"><strong>Your leg (${escapeHtml(chainLong(ownChain))})</strong><br>${explorerTx(ownChain, ownLock)}</div>` +
    `<div class="leg card"><strong>Counterparty (${escapeHtml(chainLong(cpChain))})</strong><br>${explorerTx(cpChain, cpLock)}</div>` +
    `</div>` +
    // #270: what this swap costs and what you net. The funding miner fee is set by your own wallet in
    // interactive mode (unknown here until you sign), so it is named rather than numbered; "you
    // receive" is the counter-leg, less a small claim miner fee you pay when you claim it.
    (function () {
      const youLock = s.role === "maker" ? s.maker_amount_sat : s.taker_amount_sat;
      const youRecv = s.role === "maker" ? s.taker_amount_sat : s.maker_amount_sat;
      const vfee = s.voluntary_fee_sat;
      const row = (t) => `<p class="muted" style="margin:.15rem 0">${t}</p>`;
      return (
        `<div class="card"><strong>What this swap costs you</strong>` +
        row(`You lock: <strong>${fmtSats(youLock)} ${chainTag(ownChain)}</strong>`) +
        row(
          vfee != null
            ? `Voluntary fee: -${fmtSats(vfee)} ${chainTag(ownChain)} (to the protocol fee address)`
            : "Voluntary fee: none",
        ) +
        row("Funding miner fee: set by your wallet (you sign the funding transaction)") +
        row(
          `You receive: ~<strong>${fmtSats(youRecv)} ${chainTag(cpChain)}</strong> (the counter-leg, less a small claim miner fee)`,
        ) +
        `</div>`
      );
    })() +
    // Once the secret is on chain the swap settles by claims, so the refund countdown no longer
    // applies; hiding it avoids the "refund available" text looking like a refund is happening (#275).
    (c.refund_in_blocks != null && !s.secret_revealed ? `<p class="muted">Refund available in ${Math.max(0, c.refund_in_blocks)} blocks (if it stalls).</p>` : "") +
    `<p class="muted">Funds are safe: this ends claimed or refunded, always.</p>` +
    // E2 (design 0017): when funding is parked for the user, show the PSBT handoff.
    (s.pending_lock_psbt
      ? `<div class="card" style="border-left:3px solid var(--orange)">` +
        `<p><strong>Fund your lock (${chainShort(ownChain)})</strong></p>` +
        (s.awaiting_external_funding
          ? // #291 output-only (design 0032): the daemon's PSBT is inputless, so Sparrow/Shrike cannot
            // open it. Tell the user to pay the exact outputs from their own wallet instead.
            `<p class="muted">This swap is waiting for you to fund your lock from your own wallet. Your ` +
            `wallet cannot open the daemon's template (it has no inputs). Instead, create a normal send ` +
            `that pays <strong>exactly</strong> these outputs, then sign and paste the signed PSBT back:</p>` +
            `<div class="card" style="margin:.3rem 0">` +
            (s.funding_outputs || [])
              .map(
                (o) =>
                  `<div class="row between" style="gap:.5rem"><span><strong>${fmtSats(o.sats)} ${chainShort(ownChain)}</strong> to</span>` +
                  `<code class="copyable" style="word-break:break-all">${escapeHtml(o.address)}</code></div>`,
              )
              .join("") +
            `</div>` +
            `<p class="muted"><strong>Use coin control</strong> to spend a coin that is safe on the ` +
            `${chainShort(ownChain)} chain (a split coin), so your input cannot be replayed on the other ` +
            `chain. <strong>Sign without broadcasting</strong>, then paste the signed PSBT here so the ` +
            `engine broadcasts it. <a href="https://twentyonelife.github.io/sovereign-swap/guide/run-your-own" target="_blank" rel="noopener noreferrer">Funding guide</a>.</p>`
          : `<p class="muted">This swap is waiting for you to fund your lock. Copy the unsigned PSBT, sign it ` +
            `in your own wallet (Sparrow for ${chainShort("btc")}, Shrike for ${chainShort("xbtc")}), and paste the signed PSBT back. Your keys ` +
            `never leave your wallet. <a href="https://twentyonelife.github.io/sovereign-swap/guide/run-your-own" target="_blank" rel="noopener noreferrer">Signing guide</a>.</p>` +
            `<p class="muted"><strong>Do not broadcast it from your wallet.</strong> Paste it here so the ` +
            `engine broadcasts it as part of the swap. Broadcasting it yourself can strand your coins in a ` +
            `lock only the engine can refund.</p>` +
            `<label>Unsigned PSBT (copy)<textarea readonly rows="3" class="copyable" id="unsigned-psbt">${escapeHtml(s.pending_lock_psbt)}</textarea></label>` +
            `<div class="row" style="justify-content:flex-end;gap:.4rem"><button class="ghost" type="button" id="qr-psbt" title="Show the unsigned PSBT as an animated QR to scan with an air-gapped signer (SeedSigner, Coldcard Q)">Show QR</button><button class="ghost" type="button" id="copy-psbt">Copy</button></div>` +
            `<div id="qr-box" class="hidden" style="text-align:center;margin:.4rem 0"><canvas id="qr-canvas" width="340" height="340" style="max-width:100%;image-rendering:pixelated;background:#fff;border-radius:4px"></canvas><p class="muted" id="qr-label" style="margin:.2rem 0"></p></div>`) +
        `<label>Signed PSBT (paste)<textarea id="signed-psbt" rows="3" placeholder="cHNidP8B…"></textarea>` +
        `<span class="muted" style="font-size:.85em">Paste the signed PSBT in Base64 (it starts with <code>cHNidP8B</code>), not a raw transaction.</span></label>` +
        `<div class="row" style="justify-content:space-between;gap:.4rem"><span style="display:flex;gap:.4rem"><button class="ghost" type="button" id="paste-psbt">Paste</button><button class="ghost" type="button" id="scan-psbt" title="Scan the signed PSBT back from an air-gapped signer's QR (camera or image)">Scan QR</button></span><button class="primary" id="submit-psbt">Submit signed PSBT</button></div>` +
        `<p class="muted" id="psbt-msg"></p></div>`
      : "");
  if (s.pending_lock_psbt) {
    const ta = live.querySelector("#signed-psbt");
    // Restore any draft the user had typed and keep it in sync, so a refresh never loses it (#265).
    if (ta) {
      if (psbtDrafts[id]) ta.value = psbtDrafts[id];
      ta.addEventListener("input", () => {
        psbtDrafts[id] = ta.value;
      });
    }
    const copyBtn = live.querySelector("#copy-psbt");
    if (copyBtn)
      copyBtn.onclick = () => {
        const u = live.querySelector("#unsigned-psbt");
        if (!u) return;
        const done = () => {
          copyBtn.textContent = "Copied";
          setTimeout(() => (copyBtn.textContent = "Copy"), 1200);
        };
        if (navigator.clipboard)
          navigator.clipboard.writeText(u.value).then(done, () => u.select());
        else {
          u.select();
          document.execCommand("copy");
          done();
        }
      };
    const pasteBtn = live.querySelector("#paste-psbt");
    if (pasteBtn)
      pasteBtn.onclick = async () => {
        try {
          const t = await navigator.clipboard.readText();
          if (ta && t) {
            ta.value = t.trim();
            psbtDrafts[id] = ta.value;
          }
        } catch (e) {
          if (ta) ta.focus(); // clipboard read blocked: let the user paste manually
        }
      };
    const scanBtn = live.querySelector("#scan-psbt");
    if (scanBtn)
      scanBtn.onclick = () =>
        startPsbtScan((psbt) => {
          if (ta) {
            ta.value = psbt;
            psbtDrafts[id] = psbt;
            const m = live.querySelector("#psbt-msg");
            if (m) m.textContent = "✓ Scanned a signed PSBT. Review, then Submit.";
          }
        });
    const btn = live.querySelector("#submit-psbt");
    if (btn)
      btn.onclick = async () => {
        const psbt = (live.querySelector("#signed-psbt").value || "").trim();
        const msg = live.querySelector("#psbt-msg");
        if (!psbt) {
          msg.textContent = "Paste the signed PSBT first.";
          return;
        }
        // #302: a valid value is a Base64 PSBT (the `psbt\xff` magic encodes to `cHNidP8B`). Catch a raw
        // tx hex, a partial copy, or a wallet export here, before it fails mid-swap on a parked lock.
        if (!psbt.startsWith("cHNidP8B")) {
          msg.textContent =
            "That is not a Base64 PSBT (it should start with cHNidP8B). Paste the signed PSBT, not a raw transaction or a partial copy.";
          return;
        }
        msg.textContent = "Submitting…";
        try {
          await api("POST", "/swaps/" + id + "/signed-psbt", { psbt });
          delete psbtDrafts[id];
          msg.textContent = "Funded. The swap will proceed.";
          fillSwapDetail(id, live);
        } catch (e) {
          const err = (e.data && e.data.error) || "rejected";
          msg.textContent =
            err === "NoLongerFundable"
              ? "This swap has ended and can no longer be funded. Do not broadcast the signed transaction; discard it."
              : err === "NotYetFundable"
                ? "This swap is not ready to fund yet (waiting on the counterparty). Keep the signed PSBT and submit it again in a moment."
                : err;
        }
      };
    // #274: animated UR QR of the unsigned PSBT for air-gapped signers. Only the descriptor-backed
    // branch has #unsigned-psbt (output-only parks an inputless PSBT no QR signer can sign, #261).
    const qrBtn = live.querySelector("#qr-psbt");
    if (qrBtn) {
      const psbt = s.pending_lock_psbt;
      const cached = () => qrParts[id] && qrParts[id].psbt === psbt;
      const setLabel = () => (qrBtn.textContent = qrShown[id] ? "Hide QR" : "Show QR");
      // Fetch (if this exact PSBT is not cached) the UR parts, then start/continue the animation.
      const open = async (resetFrame) => {
        if (!cached()) {
          qrBtn.textContent = "Encoding…";
          try {
            const r = await api("POST", "/psbt/ur", { psbt });
            qrParts[id] = { psbt, parts: r.parts || [] };
          } catch (e) {
            qrShown[id] = false;
            setLabel();
            const m = live.querySelector("#psbt-msg");
            if (m) m.textContent = "Could not build the QR: " + ((e.data && e.data.error) || "error");
            return;
          }
        }
        if (resetFrame) qrFrame = 0;
        setLabel();
        startQrAnim(id);
      };
      qrBtn.onclick = () => {
        if (qrShown[id]) {
          qrShown[id] = false;
          stopQrAnim();
          const box = live.querySelector("#qr-box");
          if (box) box.classList.add("hidden");
          setLabel();
          return;
        }
        qrShown[id] = true;
        open(true);
      };
      // Re-attach after a poll rebuilt the panel, if the user had it open: continue the animation,
      // refetching only if the parked PSBT changed (so the QR never shows a stale PSBT, #274).
      if (qrShown[id]) open(false);
    }
  }
}

// Refresh the open swap's detail each tick: confirmations and the refund countdown change per block
// without a phase change, so the event stream alone would not catch them.
setInterval(() => {
  if (!$("#swaps").classList.contains("active")) return;
  const st = $("#swaps-table")._v;
  if (st && st.open) {
    const box = $("#swaps-table").querySelector(".detail-box");
    if (box) fillSwapDetail(st.open, box);
  }
}, 30000);

// --- live updates (fetch stream keeps auth in the header) ---
async function subscribe() {
  try {
    const r = await fetch("/events", { headers: { Authorization: "Bearer " + TOKEN } });
    const reader = r.body.getReader();
    const dec = new TextDecoder();
    let buf = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let i;
      while ((i = buf.indexOf("\n\n")) >= 0) {
        const frame = buf.slice(0, i);
        buf = buf.slice(i + 2);
        if (frame.startsWith("data:")) onEvent();
      }
    }
  } catch (e) {
    /* reconnect below */
  }
  setTimeout(subscribe, 3000);
}
function onEvent() {
  const active = $(".view.active").id;
  const st = active === "swaps" && $("#swaps-table")._v;
  if (st && st.open) {
    // A swap detail is open: refresh only it (confirmations/phase change per block), so the whole
    // table is not torn down on every event and the open signing inputs survive (#265). The row list
    // catches up on the next tab switch, detail close, or 30s tick.
    const box = $("#swaps-table").querySelector(".detail-box");
    if (box) fillSwapDetail(st.open, box);
  } else {
    refresh(active); // re-renders the active table, which re-fills any open inline detail
  }
  loadStatus();
}

function refresh(tab) {
  if (tab === "market") loadMarket();
  else if (tab === "swaps") loadSwaps();
  else if (tab === "history") loadHistory();
  else if (tab === "split") loadSplit();
}

// ---- Split tab: separate a pre-fork coin (classify -> build -> sign -> submit -> verify). The money
// steps are the daemon's; this is the guided, non-custodial front end. Handlers are wired once (CSP
// forbids inline onclick), and the per-step <p> shows progress/errors. ----
let splitJob = null; // { coin: {txid,vout}|null, job_id, txid }
let splitWired = false;
function splitErr(e) {
  return "error: " + ((e.data && e.data.error) || e.status || e.message || e);
}
function shortTxid(t) {
  return t.length > 14 ? t.slice(0, 8) + "…" + t.slice(-4) : t;
}
function loadSplit() {
  if (splitWired) return;
  splitWired = true;
  splitJob = { coin: null, job_id: null, txid: null };
  const build = $("#sp-build"), step1 = $("#sp-step1"), coinsBox = $("#sp-coins");
  // Any change to the inputs clears a prior coin selection.
  const reset = () => { splitJob.coin = null; build.disabled = true; coinsBox.innerHTML = ""; step1.textContent = ""; };
  ["#sp-addr", "#sp-coin"].forEach((s) => $(s).addEventListener("input", reset));
  const select = (txid, vout, note) => {
    splitJob.coin = { txid, vout: Number(vout) };
    build.disabled = false;
    step1.textContent = "✓ " + note + ' Now click "Build the split".';
  };
  const postNote = (n) => (n ? " (" + n + " other coin(s) here are post-fork and already safe.)" : "");

  $("#sp-classify").addEventListener("click", async () => {
    coinsBox.innerHTML = ""; splitJob.coin = null; build.disabled = true;
    const coinField = ($("#sp-coin").value || "").trim();
    const addrField = ($("#sp-addr").value || "").trim();
    // Advanced path: a specific coin as txid:vout.
    if (coinField) {
      const [txid, voutS] = coinField.split(":");
      if (!txid) { step1.textContent = "The coin must be txid:vout."; return; }
      step1.textContent = "Checking the coin…";
      try {
        const r = await api("POST", "/split/classify", { txid: txid.trim(), vout: Number(voutS || 0) });
        if (r.needs_split) select(txid.trim(), Number(voutS || 0), "Pre-fork coin, it needs protecting.");
        else step1.textContent = "This coin is already chain-specific; it does not need protecting.";
      } catch (e) { step1.textContent = "✗ " + splitErr(e); }
      return;
    }
    // Primary path: scan an address for its coins.
    if (!addrField) { step1.textContent = "Enter your BTC (SHA256) address (or a specific coin)."; return; }
    step1.textContent = "Scanning the chain for coins at this address… on mainnet this can take a few minutes.";
    try {
      // The scan runs async on the node (#206: scantxoutset is minutes on mainnet). POST starts it and
      // returns a scan id; poll until it is done (or errors / times out).
      const start = await api("POST", "/split/scan", { address: addrField });
      const scanId = start.scan_id;
      let coins = null;
      for (let i = 0; i < 220 && coins === null; i++) {
        await new Promise((res) => setTimeout(res, 3000));
        const st = await api("GET", "/split/scan/" + scanId);
        if (st.status === "done") coins = st.coins || [];
        else if (st.status === "error") throw new Error(st.error || "scan failed");
      }
      if (coins === null) throw new Error("scan timed out; please try again");
      const pre = coins.filter((c) => c.needs_split);
      const post = coins.length - pre.length;
      if (pre.length === 0) {
        step1.textContent = "No pre-fork coins to protect at this address." + postNote(post);
      } else if (pre.length === 1) {
        select(pre[0].txid, pre[0].vout, "Found 1 coin to protect, " + fmtSats(pre[0].value_sat) + " BTC." + postNote(post));
      } else {
        step1.textContent = "This address has " + pre.length + " coins to protect. Pick one:" + postNote(post);
        pre.forEach((c) => {
          const b = document.createElement("button");
          b.className = "ghost";
          b.style.margin = ".25rem .25rem 0 0";
          b.textContent = fmtSats(c.value_sat) + " BTC  (" + shortTxid(c.txid) + ":" + c.vout + ")";
          b.addEventListener("click", () => {
            coinsBox.querySelectorAll("button").forEach((x) => (x.style.outline = ""));
            b.style.outline = "2px solid var(--orange)";
            select(c.txid, c.vout, "Selected " + fmtSats(c.value_sat) + " BTC.");
          });
          coinsBox.appendChild(b);
        });
      }
    } catch (e) { step1.textContent = "✗ " + splitErr(e); }
  });

  $("#sp-build").addEventListener("click", async () => {
    if (!splitJob.coin) { step1.textContent = "Find or pick a coin to protect first."; return; }
    const dest = $("#sp-dest").value.trim();
    step1.textContent = "Building the unsigned transaction…";
    try {
      // A destination is needed only for a coin you hold; for a coin in the swap's own hot funding
      // wallet the daemon picks one and signs the input itself, so send dest only when you entered one.
      const body = { sha_coins: [splitJob.coin] };
      if (dest) body.dest = dest;
      const r = await api("POST", "/split/build", body);
      splitJob.job_id = r.job_id;
      if (r.daemon_signed) {
        // #314: the coin is in the swap's hot funding wallet; there is no PSBT for you to sign. The
        // daemon co-signs the coin and the marker and broadcasts, so submit the built PSBT straight through.
        step1.textContent = "✓ Built (hot funding-wallet coin). Fee " + fmtSats(r.fee_sat) + " XBT. Co-signing and broadcasting…";
        const s = await api("POST", "/split/submit", { job_id: r.job_id, psbt: r.psbt });
        splitJob.txid = s.txid;
        $("#sp-verify-card").classList.remove("hidden");
        step1.textContent = "✓ Broadcast on BTC (Blake2b). txid " + s.txid;
        $("#sp-verify-card").scrollIntoView({ behavior: "smooth", block: "start" });
        return;
      }
      $("#sp-psbt").value = r.psbt;
      $("#sp-sign-card").classList.remove("hidden");
      step1.textContent = "✓ Built. Fee " + fmtSats(r.fee_sat) + " XBT. Sign it in step 3.";
      $("#sp-sign-card").scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (e) {
      // #321: a coin YOU hold needs a destination; a coin in the swap's own funding wallet does not (the
      // daemon fills it). Turn the bare "dest required" into that explanation instead of a raw error.
      const emsg = (e && e.data && e.data.error) || "";
      if (/dest required/i.test(emsg)) {
        step1.textContent =
          "Enter a BTC (Blake2b) destination address above: this coin is yours to control, so the split needs to know where to send the protected value. (A coin held by the swap's own funding wallet does not need one.)";
      } else {
        step1.textContent = "✗ " + splitErr(e);
      }
    }
  });
  $("#sp-scan").addEventListener("click", () =>
    startPsbtScan((psbt) => {
      $("#sp-signed").value = psbt;
      $("#sp-step2").textContent = "✓ Scanned a signed transaction. Review, then Submit.";
    }),
  );
  $("#sp-submit").addEventListener("click", async () => {
    const psbt = $("#sp-signed").value.trim();
    if (!psbt) { $("#sp-step2").textContent = "Paste your signed PSBT first."; return; }
    $("#sp-step2").textContent = "Checking your signature, co-signing the marker, broadcasting…";
    try {
      const r = await api("POST", "/split/submit", { job_id: splitJob.job_id, psbt });
      splitJob.txid = r.txid;
      $("#sp-verify-card").classList.remove("hidden");
      $("#sp-step2").textContent = "✓ Broadcast on BTC (Blake2b). txid " + r.txid;
      $("#sp-verify-card").scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (e) { $("#sp-step2").textContent = "✗ " + splitErr(e); }
  });
  $("#sp-verify").addEventListener("click", async () => {
    $("#sp-step3").textContent = "Verifying on the BTC (SHA256) node…";
    try {
      const r = await api("POST", "/split/verify", { txid: splitJob.txid });
      $("#sp-step3").textContent = r.final
        ? "✓ FINAL: replay not possible. Your BTC (SHA256) coin is now safe to spend."
        : r.separated
          ? "Separated, but only " + r.confirmations + "/" + r.min_confirmations + " BTC (Blake2b) confirmations, wait a little longer."
          : "Not separated yet. Check the transaction confirmed on BTC (Blake2b).";
    } catch (e) { $("#sp-step3").textContent = "✗ " + splitErr(e); }
  });
}

loadStatus();
loadReference();
loadMarket();
subscribe();
setInterval(() => {
  loadStatus();
  loadReference();
}, 15000);
