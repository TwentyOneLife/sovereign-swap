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
    short: "XBT",
    long: "BTC (Blake2b)",
    note: "Bitcoin Blake2b, a different asset from Bitcoin",
    url: "https://bitcoinknots.org/",
  },
};
const chainShort = (c) => (CHAIN[c] || {}).short || String(c).toUpperCase();
const chainLong = (c) => (CHAIN[c] || {}).long || String(c).toUpperCase();
const chainNote = (c) => (CHAIN[c] || {}).note || String(c).toUpperCase();
const chainUrl = (c) => (CHAIN[c] || {}).url || "";
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
  const relayTitle = `Nostr relay(s) for offer discovery: ${s.relays > 0 ? `${s.relays} connected` : "none connected"}`;
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
    item(onoff(s.relays > 0), relayTitle, "relay"),
    item(priceState, priceTitle, "price"),
    `<span class="stat" title="${activeTitle}">${s.active_swaps ?? "?"} active</span>`,
  ].join(sep);
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

async function loadMarket() {
  const offers = await api("GET", "/offers").catch(() => []);
  $("#offers-empty").style.display = offers.length ? "none" : "block";
  mountTable($("#offers"), {
    rows: offers,
    rowId: (o) => o.id,
    defaultSort: 0, // Seen, newest first
    defaultDir: "desc",
    columns: [
      { label: "Seen", get: (o) => o.seen_at || 0, cell: (o) => { const t = fmtTime(o.seen_at); return `<span title="${escapeHtml(t.title)}">${t.text}</span>`; } },
      { label: "Selling", get: (o) => o.sell_chain, cell: (o) => chainShort(o.sell_chain) },
      { label: "Amount", num: true, get: (o) => o.amount_sat, cell: (o) => fmtSats(o.amount_sat) },
      { label: "For", num: true, get: (o) => o.counter_amount_sat, cell: (o) => `${fmtSats(o.counter_amount_sat)} ${chainShort(o.taker_chain)}` },
      { label: "Rate", num: true, get: (o) => o.counter_amount_sat / o.amount_sat, cell: (o) => fmtRate(o.counter_amount_sat / o.amount_sat) },
    ],
    actions: () => `<button class="link take-btn">Take</button> `,
    wireActions: (tr, o) => { const b = tr.querySelector(".take-btn"); if (b) b.addEventListener("click", (e) => { e.stopPropagation(); takeSheet(o); }); },
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

function offerForm(o) {
  if (o) {
    // Take: the terms are the maker's; you take the whole offer, nothing to set.
    return `<div class="row between"><h2>Take offer</h2>
        <button class="link" id="f-x" title="Close this dialog (changes nothing)">✕</button></div>
      <p class="muted">Selling <strong>${fmtSats(o.amount_sat)} ${chainShort(o.sell_chain)}</strong> for
        <strong>${fmtSats(o.counter_amount_sat)} ${chainShort(o.taker_chain)}</strong> ·
        rate ${fmtRate(o.counter_amount_sat / o.amount_sat)}.</p>
      <div class="warn"><strong>Non-custodial.</strong> Your keys never leave your node; a swap ends claimed or refunded.</div>
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
    <label>Amount <input id="f-amount" placeholder="0.5"></label>
    <p id="f-market" class="muted">Loading the market rate…</p>
    <label title="Your margin off the nonkyc market rate, in whole percent (1% steps). Positive earns you more as the maker; negative undercuts the market to fill faster. The rate comes from nonkyc; you choose only the margin.">
      Your maker margin (%) <input id="f-margin" type="number" step="1" value="0"></label>
    <p id="f-eff" class="muted"></p>
    <details id="f-adv"><summary class="muted" style="cursor:pointer">Advanced: set an exact counter amount instead</summary>
      <label title="A specific integer counter amount for the whole offer. Still checked against the market band. Leave blank to use the margin above.">
        Exact counter amount <input id="f-counter" placeholder="leave blank to use the margin"></label>
    </details>
    <div id="f-d6" class="warn hidden"></div>
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
  openSheet(offerForm(null));
  let ref = null; // { rate: BTC per xBTC, band: price_band_pct, verify } or null when unavailable
  const go = $("#f-go");

  // The market price (counter coin per unit of the sold coin) for the current direction.
  const marketPrice = () =>
    !ref ? null : $("#f-chain").value === "xbtc" ? ref.rate : 1 / ref.rate;

  async function loadReference() {
    try {
      const r = await api("GET", "/reference-rate");
      ref =
        r.enabled && !r.error && isFinite(r.rate) && r.rate > 0
          ? { rate: r.rate, band: Number.isFinite(r.price_band_pct) ? r.price_band_pct : 10, verify: r.verify_url }
          : null;
    } catch (e) {
      ref = null;
    }
    recompute();
  }

  function recompute() {
    const market = $("#f-market"), eff = $("#f-eff"), d6 = $("#f-d6");
    const counterRaw = ($("#f-counter") && $("#f-counter").value.trim()) || "";
    const sell = $("#f-chain").value, taker = sell === "xbtc" ? "btc" : "xbtc";
    const amount = parseBtc($("#f-amount").value);
    if (!ref) {
      // D6: no reference, no market-derived price. Only the Advanced exact-counter path can publish.
      market.textContent = "";
      eff.textContent = "";
      d6.classList.remove("hidden");
      d6.innerHTML =
        "<strong>Market rate unavailable.</strong> The nonkyc reference is off or unreachable, so an offer cannot be priced from the market. Enable the price reference, or set an exact counter amount under Advanced.";
      go.disabled = !counterRaw;
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
    if (counterRaw) {
      // Advanced: send the exact counter; show its implied rate and deviation from the market.
      go.disabled = false;
      const counter = parseBtc(counterRaw);
      if (counter !== null && amount) {
        const off = (counter / amount / mp - 1) * 100;
        const warn = Math.abs(off) > ref.band
          ? ` <span style="color:var(--orange)">⚠ outside the ±${ref.band}% band; will be rejected</span>`
          : "";
        eff.innerHTML = `Exact: ${fmtSats(counter)} ${chainShort(taker)} · rate ${fmtRate(counter / amount)} (${off >= 0 ? "+" : ""}${off.toFixed(1)}% vs market)${warn}`;
      } else {
        eff.textContent = "";
      }
      return;
    }
    // Market-derived: price = market * (1 + margin/100); the daemon finalizes the counter at publish.
    const margin = parseInt($("#f-margin").value, 10) || 0;
    const overBand = Math.abs(margin) > ref.band;
    go.disabled = overBand;
    const profit = margin > 0
      ? `you ask ${margin}% above market (earn more; may fill slower)`
      : margin < 0
        ? `you undercut market by ${-margin}% (fill faster; earn less)`
        : "exactly the market rate";
    if (overBand) {
      eff.innerHTML = `<span style="color:var(--orange)">⚠ ${margin}% exceeds the ±${ref.band}% band; lower the margin.</span>`;
      return;
    }
    const price = mp * (1 + margin / 100);
    eff.innerHTML = amount
      ? `You offer ${fmtSats(amount)} ${chainShort(sell)} for ~${fmtSats(Math.ceil(amount * price))} ${chainShort(taker)} · rate ${fmtRate(price)} (${margin >= 0 ? "+" : ""}${margin}% vs market), ${profit}.`
      : `Margin ${margin >= 0 ? "+" : ""}${margin}%, ${profit}. Enter an amount to see the total.`;
  }

  $("#f-chain").onchange = recompute;
  $("#f-amount").addEventListener("input", recompute);
  $("#f-margin").addEventListener("input", recompute);
  if ($("#f-counter")) $("#f-counter").addEventListener("input", recompute);
  loadReference();

  go.onclick = async () => {
    const amount = parseBtc($("#f-amount").value);
    if (amount === null) return ($("#f-msg").textContent = "Enter a valid amount.");
    const body = { sell_chain: $("#f-chain").value, amount_sat: amount, min_amount_sat: amount };
    const counterRaw = ($("#f-counter") && $("#f-counter").value.trim()) || "";
    if (counterRaw) {
      const counter = parseBtc(counterRaw);
      if (counter === null) return ($("#f-msg").textContent = "Enter a valid counter amount.");
      body.counter_amount_sat = counter;
    } else {
      // Market-derived path: send only the whole-percent margin; the daemon prices it off the live
      // reference, so the published rate is the market rate at publish time, always in band.
      body.margin_pct = parseInt($("#f-margin").value, 10) || 0;
    }
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
  openSheet(offerForm(o));
  $("#f-go").onclick = async () => {
    try {
      const r = await api("POST", `/offers/${o.id}/take`, { amount_sat: o.amount_sat });
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
      { label: "Direction", get: (s) => s.maker_chain, cell: (s) => `${chainShort(s.maker_chain)}→${chainShort(s.taker_chain)}` },
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

// A lock (txid + confirmation state) rendered for the live per-swap detail.
function explorerTx(chain, lock) {
  if (!lock || !lock.txid) return "not locked yet";
  const state = `${lock.confirmations == null ? "unconfirmed" : lock.confirmations + " conf"} · ${lock.spent ? "spent" : "locked"}`;
  return `${explorerLink(chain, lock.txid)}<br>${state}`;
}

// History / ledger (#67): the daemon derives per-swap entries + totals from its own records at
// GET /history; this view only renders them. Each entry already carries the realized rate and the
// voluntary fee paid, so the detail needs no extra fetch (unlike the live Swaps detail).
async function loadHistory() {
  const h = await api("GET", "/history").catch(() => null);
  // The ledger lists only terminal swaps; any still in flight show in the Swaps tab (and are counted
  // as "in flight" in the totals line below).
  const entries = ((h && h.swaps) || []).filter(isTerminal);
  const t = h && h.totals;
  $("#history-empty").style.display = entries.length ? "none" : "block";
  $("#history-totals").innerHTML = t
    ? `${t.count} swap(s) · ${t.done} done · ${t.refunded} refunded · ${t.abandoned} abandoned` +
      (t.active ? ` · ${t.active} in flight` : "") +
      ` · volume ${fmtSats(t.volume_sat.btc)} ${chainShort("btc")} / ${fmtSats(t.volume_sat.xbtc)} ${chainShort("xbtc")}` +
      ` · voluntary fee paid ${fmtSats(t.voluntary_fee_paid.total_sat)} over ${t.voluntary_fee_paid.swaps} swap(s)`
    : "";
  mountTable($("#history-table"), {
    rows: entries,
    rowId: (s) => s.id,
    defaultSort: 0, // Started, newest first
    defaultDir: "desc",
    columns: [
      { label: "Started", get: (s) => s.started_at || 0, cell: (s) => { const tt = fmtTime(s.started_at); return `<span title="${escapeHtml(tt.title)}">${tt.text}</span>`; } },
      { label: "Swap", get: (s) => s.id, cell: (s) => "#" + s.id.slice(0, 6) },
      { label: "Role", get: (s) => s.role, cell: (s) => s.role },
      { label: "Direction", get: (s) => s.maker_chain, cell: (s) => `${chainShort(s.maker_chain)}→${chainShort(s.taker_chain)}` },
      { label: "Rate", num: true, get: (s) => s.rate || 0, cell: (s) => fmtRate(s.rate) },
      { label: "Fee paid", num: true, get: (s) => s.voluntary_fee_paid_sat || 0, cell: (s) => s.voluntary_fee_paid_sat == null ? "-" : fmtSats(s.voluntary_fee_paid_sat) },
      { label: "Phase", get: (s) => s.phase, cell: (s) => { const cls = isTerminal(s) ? "phase-" + s.phase : "phase-active"; return `<span class="pill ${cls}">${s.phase}</span>`; } },
    ],
    detailInto: (s, box) => {
      const ownChain = s.role === "maker" ? s.maker_chain : s.taker_chain;
      box.innerHTML =
        `<p class="muted">${s.role} · ${fmtSats(s.maker_amount_sat)} ${chainShort(s.maker_chain)} for ` +
        `${fmtSats(s.taker_amount_sat)} ${chainShort(s.taker_chain)} · realized rate ${fmtRate(s.rate)}` +
        (s.secret_revealed ? " · secret revealed" : "") + `</p>` +
        `<p class="muted">Voluntary fee paid: ${s.voluntary_fee_paid_sat == null ? "none" : fmtSats(s.voluntary_fee_paid_sat) + " " + chainShort(ownChain)}</p>` +
        `<p class="muted">Your lock (${chainShort(ownChain)}): ${explorerLink(ownChain, s.our_lock_txid)}</p>` +
        `<p class="muted">The counterparty leg's txids are on the live Swaps view while a swap is in flight.</p>`;
    },
  });
}

async function fillSwapDetail(id, box) {
  box.innerHTML = "Loading…";
  const s = await api("GET", "/swaps/" + id).catch(() => null);
  const st = $("#swaps-table")._v;
  if (!st || st.open !== id) return; // row closed or changed during the fetch
  const live = $("#swaps-table").querySelector(".detail-box");
  if (!live) return;
  if (!s) { live.innerHTML = `<span class="muted">detail unavailable</span>`; return; }
  const c = s.chain || {};
  // Our own lock is on our side of the swap, which is the taker lock when we are the taker (#73).
  const ownChain = s.role === "maker" ? s.maker_chain : s.taker_chain;
  const cpChain = s.role === "maker" ? s.taker_chain : s.maker_chain;
  const ownLock = s.role === "maker" ? c.maker_lock : c.taker_lock;
  const cpLock = s.role === "maker" ? c.taker_lock : c.maker_lock;
  live.innerHTML =
    `<p class="muted">${s.role} · ${fmtSats(s.maker_amount_sat)} ${chainShort(s.maker_chain)} for ${fmtSats(s.taker_amount_sat)} ${chainShort(s.taker_chain)}` +
    (s.secret_revealed ? " · secret revealed" : "") + `</p>` +
    `<div class="legs">` +
    `<div class="leg card"><strong>Your leg (${chainLink(ownChain)})</strong><br>${explorerTx(ownChain, ownLock)}</div>` +
    `<div class="leg card"><strong>Counterparty (${chainLink(cpChain)})</strong><br>${explorerTx(cpChain, cpLock)}</div>` +
    `</div>` +
    (c.refund_in_blocks != null ? `<p class="muted">Refund available in ${Math.max(0, c.refund_in_blocks)} blocks (if it stalls).</p>` : "") +
    `<p class="muted">Funds are safe: this ends claimed or refunded, always.</p>` +
    // E2 (design 0017): when funding is parked for the user, show the PSBT handoff.
    (s.pending_lock_psbt
      ? `<div class="card" style="border-left:3px solid var(--orange)">` +
        `<p><strong>Sign your funding (${chainShort(ownChain)})</strong></p>` +
        `<p class="muted">This swap is waiting for you to fund your lock. Copy the unsigned PSBT, sign it ` +
        `in your own wallet (Sparrow for ${chainShort("btc")}, Shrike for ${chainShort("xbtc")}), and paste the signed PSBT back. Your keys ` +
        `never leave your wallet.</p>` +
        `<p class="muted"><strong>Do not broadcast it from your wallet.</strong> Paste it here so the ` +
        `engine broadcasts it as part of the swap. Broadcasting it yourself can strand your coins in a ` +
        `lock only the engine can refund.</p>` +
        `<label>Unsigned PSBT (copy)<textarea readonly rows="3" class="copyable">${escapeHtml(s.pending_lock_psbt)}</textarea></label>` +
        `<label>Signed PSBT (paste)<textarea id="signed-psbt" rows="3" placeholder="cHNidP8B…"></textarea></label>` +
        `<div class="row" style="justify-content:flex-end"><button class="primary" id="submit-psbt">Submit signed PSBT</button></div>` +
        `<p class="muted" id="psbt-msg"></p></div>`
      : "");
  if (s.pending_lock_psbt) {
    const btn = live.querySelector("#submit-psbt");
    if (btn)
      btn.onclick = async () => {
        const psbt = (live.querySelector("#signed-psbt").value || "").trim();
        const msg = live.querySelector("#psbt-msg");
        if (!psbt) {
          msg.textContent = "Paste the signed PSBT first.";
          return;
        }
        msg.textContent = "Submitting…";
        try {
          await api("POST", "/swaps/" + id + "/signed-psbt", { psbt });
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
  refresh(active); // re-renders the active table, which re-fills any open inline detail
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
      const r = await api("POST", "/split/scan", { address: addrField });
      const coins = r.coins || [];
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
    if (!dest) { step1.textContent = "Enter your BTC (Blake2b) destination address first."; return; }
    step1.textContent = "Building the unsigned transaction…";
    try {
      const r = await api("POST", "/split/build", { sha_coins: [splitJob.coin], dest });
      splitJob.job_id = r.job_id;
      $("#sp-psbt").value = r.psbt;
      $("#sp-sign-card").classList.remove("hidden");
      step1.textContent = "✓ Built. Fee " + fmtSats(r.fee_sat) + " XBT. Sign it in step 3.";
      $("#sp-sign-card").scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (e) { step1.textContent = "✗ " + splitErr(e); }
  });
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
