"use strict";
const TOKEN = window.SWAP_TOKEN;
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

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
  if (!sec) return { text: "—", title: "" };
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
  const dot = (cls, title) => `<span class="dot ${cls}"${title ? ` title="${title}"` : ""}></span>`;
  const onoff = (ok) => (ok ? "on" : "off");
  const priceTitle =
    priceState === "on"
      ? "External price reference (nonkyc BTCB2/BTC, over Tor): live"
      : priceState === "err"
        ? "External price reference: enabled, but the fetch is failing (often a blocked Tor exit; it retries)"
        : "External price reference: off (price discovery is this relay's order book)";
  // Each dot names the exact connection it reports, so a red dot points at the right place.
  const btcTitle = `BTC node RPC: ${s.btc_node ? "reachable" : "unreachable"}`;
  const xbtcTitle = `xBTC (Bitcoin Blake2b) node RPC: ${s.xbtc_node ? "reachable" : "unreachable"}`;
  const engineTitle = `Swap engine (the daemon's tick loop): ${s.engine ? "running" : "stopped"}`;
  const relayTitle = `Nostr relay(s) for offer discovery: ${s.relays > 0 ? `${s.relays} connected` : "none connected"}`;
  const activeTitle = "Swaps currently in flight on this node";
  el.innerHTML =
    `${dot(onoff(s.btc_node), btcTitle)}BTC ${dot(onoff(s.xbtc_node), xbtcTitle)}xBTC ` +
    `${dot(onoff(s.engine), engineTitle)}engine ${dot(onoff(s.relays > 0), relayTitle)}relay ` +
    `${dot(priceState, priceTitle)}price · <span title="${activeTitle}">${s.active_swaps ?? "?"} active</span>`;
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
let lastOffers = [];

// Price context from OUR order book (no external oracle; xBTC has no liquid market to derive a rate
// from, so the offers on our relay are the price discovery). Returns the rate range and midpoint for
// a sell direction, to prefill the create form and show where the market is.
function rateHint(sellChain) {
  const rates = lastOffers
    .filter((o) => o.sell_chain === sellChain)
    .map((o) => o.counter_amount_sat / o.amount_sat)
    .filter((r) => isFinite(r) && r > 0)
    .sort((a, b) => a - b);
  if (!rates.length) return null;
  return { count: rates.length, min: rates[0], max: rates[rates.length - 1], mid: rates[Math.floor(rates.length / 2)] };
}

async function loadMarket() {
  const offers = await api("GET", "/offers").catch(() => []);
  lastOffers = offers;
  $("#offers-empty").style.display = offers.length ? "none" : "block";
  mountTable($("#offers"), {
    rows: offers,
    rowId: (o) => o.id,
    defaultSort: 0, // Seen, newest first
    defaultDir: "desc",
    columns: [
      { label: "Seen", get: (o) => o.seen_at || 0, cell: (o) => { const t = fmtTime(o.seen_at); return `<span title="${escapeHtml(t.title)}">${t.text}</span>`; } },
      { label: "Selling", get: (o) => o.sell_chain, cell: (o) => o.sell_chain.toUpperCase() },
      { label: "Amount", num: true, get: (o) => o.amount_sat, cell: (o) => fmtSats(o.amount_sat) },
      { label: "For", num: true, get: (o) => o.counter_amount_sat, cell: (o) => `${fmtSats(o.counter_amount_sat)} ${o.taker_chain.toUpperCase()}` },
      { label: "Rate", num: true, get: (o) => o.counter_amount_sat / o.amount_sat, cell: (o) => fmtRate(o.counter_amount_sat / o.amount_sat) },
    ],
    actions: () => `<button class="link take-btn">Take</button> `,
    wireActions: (tr, o) => { const b = tr.querySelector(".take-btn"); if (b) b.addEventListener("click", (e) => { e.stopPropagation(); takeSheet(o); }); },
    detailInto: (o, box) => {
      const t = fmtTime(o.seen_at);
      box.innerHTML =
        `<div class="row between"><strong>Offer #${escapeHtml(o.id.slice(0, 8))}</strong>` +
        `<button class="primary take-btn2">Take this offer</button></div>` +
        `<p class="muted">Selling <strong>${fmtSats(o.amount_sat)} ${o.sell_chain.toUpperCase()}</strong> for ` +
        `<strong>${fmtSats(o.counter_amount_sat)} ${o.taker_chain.toUpperCase()}</strong> · rate ${fmtRate(o.counter_amount_sat / o.amount_sat)} · seen ${t.text}</p>` +
        `<p class="muted">Lock windows: maker ${o.maker_lock_blocks} blk, taker ${o.taker_lock_blocks} blk · smallest take ${fmtSats(o.min_amount_sat)}.</p>`;
      const b = box.querySelector(".take-btn2");
      if (b) b.addEventListener("click", () => takeSheet(o));
    },
  });
}

function offerForm(o) {
  const sell = o ? o.sell_chain : "xbtc";
  const hint = o ? null : rateHint(sell);
  const price = o ? fmtRate(o.counter_amount_sat / o.amount_sat) : (hint ? fmtRate(hint.mid) : "0.997");
  const hintLine = hint
    ? `<p class="muted" title="From current offers on your relay; there is no external rate">Market: ${hint.count} offer(s), rate ${fmtRate(hint.min)} - ${fmtRate(hint.max)}. You set your own price.</p>`
    : o ? "" : `<p class="muted">No offers yet to compare; you set the price (the market discovers it).</p>`;
  return `<div class="row between"><h2>${o ? "Take offer" : "Create offer"}</h2>
      <button class="link" id="f-x" title="Close this dialog (changes nothing)">✕</button></div>
    <label>I am selling
      <select id="f-chain" ${o ? "disabled" : ""}>
        <option value="xbtc" ${sell === "xbtc" ? "selected" : ""}>xBTC</option>
        <option value="btc" ${sell === "btc" ? "selected" : ""}>BTC</option>
      </select></label>
    <label>Amount <input id="f-amount" value="${o ? fmtSats(o.amount_sat) : ""}" placeholder="0.5"></label>
    <label title="How much of the other coin per unit; you set it, the order book discovers the market">Price <input id="f-price" value="${price}"></label>
    ${o ? "" : '<label title="For a lopsided real rate (e.g. BTC vs the much cheaper xBTC): the exact total amount of the other coin you want for the whole amount. Overrides Price when set.">Exact counter amount (optional) <input id="f-counter" placeholder="leave blank to use Price"></label>'}
    ${hintLine}
    ${o ? "" : '<p id="f-ref" class="muted"></p><p id="f-dev" class="muted" style="color:var(--orange)"></p>'}
    <div class="warn"><strong>Non-custodial.</strong> Your keys never leave your node; a swap ends claimed or refunded.</div>
    <div class="row between">
      <button class="ghost" id="f-cancel" title="Close this dialog (does not withdraw an offer or cancel a swap)">Close</button>
      <button class="primary" id="f-go">${o ? "Take" : "Publish offer"}</button>
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
  // Re-suggest the price from the order book when the direction changes.
  $("#f-chain").onchange = () => {
    const h = rateHint($("#f-chain").value);
    if (h) $("#f-price").value = fmtRate(h.mid);
    showReference();
  };
  // Optional external reference (nonkyc, over Tor) + a fat-finger deviation warning.
  let refRate = null; // BTC per xBTC
  async function showReference() {
    const box = $("#f-ref");
    if (!box) return;
    try {
      const r = await api("GET", "/reference-rate");
      if (!r.enabled) { box.textContent = ""; refRate = null; return; }
      if (r.error) { box.textContent = "Reference unavailable (" + r.error + "); using the order book."; refRate = null; return; }
      refRate = r.rate;
      const sell = $("#f-chain").value;
      const shown = sell === "xbtc" ? r.rate : 1 / r.rate; // price is per-unit of what you sell
      const verify = r.verify_url
        ? ` · <a href="${escapeHtml(r.verify_url)}" target="_blank" rel="noopener noreferrer">verify on nonkyc</a>`
        : "";
      box.innerHTML =
        `Reference: <strong>${shown.toFixed(sell === "xbtc" ? 8 : 4)}</strong> ` +
        `(${escapeHtml(r.source)})${verify}. You still set the price.`;
    } catch (e) { box.textContent = ""; refRate = null; }
  }
  function checkDeviation() {
    const w = $("#f-dev");
    if (!w || refRate === null) return;
    const sell = $("#f-chain").value;
    const ref = sell === "xbtc" ? refRate : 1 / refRate;
    const p = parseFloat($("#f-price").value.replace(",", "."));
    const off = isFinite(p) && ref > 0 ? Math.abs(p - ref) / ref : 0;
    w.textContent = off > 0.05 ? `⚠ ${(off * 100).toFixed(0)}% from the reference - check the price.` : "";
  }
  $("#f-price").addEventListener("input", checkDeviation);
  showReference();
  $("#f-go").onclick = async () => {
    const amount = parseBtc($("#f-amount").value);
    if (amount === null) return ($("#f-msg").textContent = "Enter a valid amount.");
    const counterRaw = $("#f-counter") ? $("#f-counter").value.trim() : "";
    const body = { sell_chain: $("#f-chain").value, amount_sat: amount, min_amount_sat: amount };
    if (counterRaw) {
      // F1/F2: an exact counter amount expresses a lopsided real rate the band/price-field cannot.
      const counter = parseBtc(counterRaw);
      if (counter === null) return ($("#f-msg").textContent = "Enter a valid counter amount.");
      body.counter_amount_sat = counter;
    } else {
      const price = parseFloat($("#f-price").value.replace(",", "."));
      if (!isFinite(price)) return ($("#f-msg").textContent = "Enter a price or an exact counter amount.");
      body.price = price;
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
  const addrs = [
    { coin: "Bitcoin (BTC)", note: "the SHA-256 Bitcoin network", addr: "bc1p37x3ehmhdy6s40fuy0haw9sv9pmyjdqz5wulvm93jry4fy63ttksxja9sh" },
    { coin: "BitcoinB2B (xBTC)", note: "Bitcoin Blake2b, a different asset from Bitcoin", addr: "bc1pe62v4m0p6njpxn2ej9hx307tm0xlccnxe652vxk9r76g2qync7sqkfly4t" },
  ];
  const rows = addrs.map((a) =>
    `<label>${escapeHtml(a.coin)} <span class="muted">(${escapeHtml(a.note)})</span>` +
    `<input readonly value="${escapeHtml(a.addr)}" onclick="this.select()"></label>`,
  ).join("");
  return (
    `<div class="row between"><strong>Donate to TwentyOne.Life</strong>` +
    `<button class="link" id="f-x" title="Close">✕</button></div>` +
    `<p class="muted">These two addresses share Bitcoin's address format but are different assets on ` +
    `different networks. Send only the matching coin to each; anything sent to the other network is a ` +
    `different asset and will not arrive as intended.</p>${rows}` +
    `<div class="row" style="justify-content:flex-end"><button class="ghost" id="f-cancel">Close</button></div>`
  );
}
const donateBtn = $("#donate");
if (donateBtn) donateBtn.onclick = () => openSheet(donateSheet());

// --- swaps ---
let lastSwaps = [];
async function loadSwaps() {
  lastSwaps = await api("GET", "/swaps").catch(() => []);
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
      { label: "Direction", get: (s) => s.maker_chain, cell: (s) => `${s.maker_chain.toUpperCase()}→${s.taker_chain.toUpperCase()}` },
      { label: "Phase", get: (s) => s.phase, cell: (s) => { const cls = ["done", "refunded", "abandoned"].includes(s.phase) ? "phase-" + s.phase : "phase-active"; return `<span class="pill ${cls}">${s.phase}</span>`; } },
    ],
    detailInto: (s, box) => fillSwapDetail(s.id, box),
  });
}

// A txid rendered as a link to the operator's configured explorer (#67), or plain text when none set.
function explorerTx(chain, lock) {
  if (!lock || !lock.txid) return "not locked yet";
  const base = chain === "btc" ? statusData?.btc_explorer_url : statusData?.xbtc_explorer_url;
  const short = String(lock.txid).slice(0, 16) + "…";
  const link = base
    ? `<a href="${escapeHtml(base.replace(/\/$/, ""))}/tx/${escapeHtml(lock.txid)}" target="_blank" rel="noopener">${short}</a>`
    : short;
  const state = `${lock.confirmations == null ? "unconfirmed" : lock.confirmations + " conf"} · ${lock.spent ? "spent" : "locked"}`;
  return `${link}<br>${state}`;
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
    `<p class="muted">${s.role} · ${fmtSats(s.maker_amount_sat)} ${s.maker_chain.toUpperCase()} for ${fmtSats(s.taker_amount_sat)} ${s.taker_chain.toUpperCase()}` +
    (s.secret_revealed ? " · secret revealed" : "") + `</p>` +
    `<div class="legs">` +
    `<div class="leg card"><strong>Your leg (${ownChain.toUpperCase()})</strong><br>${explorerTx(ownChain, ownLock)}</div>` +
    `<div class="leg card"><strong>Counterparty (${cpChain.toUpperCase()})</strong><br>${explorerTx(cpChain, cpLock)}</div>` +
    `</div>` +
    (c.refund_in_blocks != null ? `<p class="muted">Refund available in ${Math.max(0, c.refund_in_blocks)} blocks (if it stalls).</p>` : "") +
    `<p class="muted">Funds are safe: this ends claimed or refunded, always.</p>`;
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
}

loadStatus();
loadReference();
loadMarket();
subscribe();
setInterval(() => {
  loadStatus();
  loadReference();
}, 15000);
