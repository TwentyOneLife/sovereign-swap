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

// --- tabs ---
$$(".tab").forEach((t) =>
  t.addEventListener("click", () => {
    $$(".tab").forEach((x) => x.classList.toggle("active", x === t));
    $$(".view").forEach((v) => v.classList.toggle("active", v.id === t.dataset.tab));
    refresh(t.dataset.tab);
  })
);

// --- status ---
async function loadStatus() {
  try {
    const s = await api("GET", "/status");
    const dot = (ok) => `<span class="dot ${ok ? "on" : "off"}"></span>`;
    $("#status").innerHTML =
      `${dot(s.btc_node)}BTC ${dot(s.xbtc_node)}xBTC ${dot(s.engine)}engine · ${s.active_swaps} active`;
  } catch (e) {
    $("#status").textContent = "daemon unreachable";
  }
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
  const body = $("#offers tbody");
  body.innerHTML = "";
  $("#offers-empty").style.display = offers.length ? "none" : "block";
  for (const o of offers) {
    const rate = (o.counter_amount_sat / o.amount_sat).toFixed(4);
    const tr = document.createElement("tr");
    tr.innerHTML =
      `<td>${o.sell_chain.toUpperCase()}</td>` +
      `<td class="num">${fmtSats(o.amount_sat)}</td>` +
      `<td class="num">${fmtSats(o.counter_amount_sat)} ${o.taker_chain.toUpperCase()}</td>` +
      `<td class="num">${rate}</td>` +
      `<td class="num"><button class="link">Take</button></td>`;
    tr.querySelector("button").onclick = () => takeSheet(o);
    body.appendChild(tr);
  }
}

function offerForm(o) {
  const sell = o ? o.sell_chain : "xbtc";
  const hint = o ? null : rateHint(sell);
  const price = o ? (o.counter_amount_sat / o.amount_sat).toFixed(4) : (hint ? hint.mid.toFixed(4) : "0.997");
  const hintLine = hint
    ? `<p class="muted" title="From current offers on your relay; there is no external rate">Market: ${hint.count} offer(s), rate ${hint.min.toFixed(4)} - ${hint.max.toFixed(4)}. You set your own price.</p>`
    : o ? "" : `<p class="muted">No offers yet to compare; you set the price (the market discovers it).</p>`;
  return `<h2>${o ? "Take offer" : "Create offer"}</h2>
    <label>I am selling
      <select id="f-chain" ${o ? "disabled" : ""}>
        <option value="xbtc" ${sell === "xbtc" ? "selected" : ""}>xBTC</option>
        <option value="btc" ${sell === "btc" ? "selected" : ""}>BTC</option>
      </select></label>
    <label>Amount <input id="f-amount" value="${o ? fmtSats(o.amount_sat) : ""}" placeholder="0.5"></label>
    <label title="How much of the other coin per unit; you set it, the order book discovers the market">Price <input id="f-price" value="${price}"></label>
    ${hintLine}
    ${o ? "" : '<p id="f-ref" class="muted"></p><p id="f-dev" class="muted" style="color:var(--orange)"></p>'}
    <div class="warn"><strong>Non-custodial.</strong> Your keys never leave your node; a swap ends claimed or refunded.</div>
    <div class="row between">
      <button class="ghost" id="f-cancel">Cancel</button>
      <button class="primary" id="f-go">${o ? "Take" : "Publish offer"}</button>
    </div>
    <p id="f-msg" class="muted"></p>`;
}

function openSheet(html) {
  $("#modal .sheet").innerHTML = html;
  $("#modal").classList.remove("hidden");
  $("#f-cancel").onclick = () => $("#modal").classList.add("hidden");
}

function createSheet() {
  openSheet(offerForm(null));
  // Re-suggest the price from the order book when the direction changes.
  $("#f-chain").onchange = () => {
    const h = rateHint($("#f-chain").value);
    if (h) $("#f-price").value = h.mid.toFixed(4);
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
      box.innerHTML = `Reference: <strong>${shown.toFixed(sell === "xbtc" ? 8 : 4)}</strong> (${r.source}). You still set the price.`;
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
    const price = parseFloat($("#f-price").value.replace(",", "."));
    if (amount === null || !isFinite(price)) return ($("#f-msg").textContent = "Enter a valid amount and price.");
    try {
      await api("POST", "/offers", {
        sell_chain: $("#f-chain").value,
        amount_sat: amount,
        price,
        min_amount_sat: amount,
      });
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

// --- swaps ---
async function loadSwaps() {
  const swaps = await api("GET", "/swaps").catch(() => []);
  const body = $("#swaps-table tbody");
  body.innerHTML = "";
  $("#swaps-empty").style.display = swaps.length ? "none" : "block";
  for (const s of swaps) {
    const cls = ["done", "refunded", "abandoned"].includes(s.phase) ? "phase-" + s.phase : "phase-active";
    const tr = document.createElement("tr");
    tr.innerHTML =
      `<td>#${s.id.slice(0, 6)}</td><td>${s.role}</td>` +
      `<td>${s.maker_chain.toUpperCase()}→${s.taker_chain.toUpperCase()}</td>` +
      `<td><span class="pill ${cls}">${s.phase}</span></td>` +
      `<td class="num"><button class="link">Detail</button></td>`;
    tr.querySelector("button").onclick = () => showSwap(s.id);
    body.appendChild(tr);
  }
}

// The open swap detail, auto-refreshed: confirmations and the refund countdown change every block
// without a phase change, so SSE alone would not catch them. Poll on a timer with a visible countdown.
const DETAIL_REFRESH = 30; // seconds
let detailId = null;
let detailNext = 0;

function showSwap(id) {
  detailId = id;
  detailNext = Date.now();
}

async function renderSwap(id) {
  const s = await api("GET", "/swaps/" + id).catch(() => null);
  if (!s || detailId !== id) return;
  const c = s.chain || {};
  const leg = (name, lock) =>
    `<div class="leg card"><strong>${name}</strong><br>` +
    (lock
      ? `tx ${String(lock.txid).slice(0, 12)}…<br>` +
        `${lock.confirmations == null ? "unconfirmed" : lock.confirmations + " conf"} · ${lock.spent ? "spent" : "locked"}`
      : "not locked yet") +
    `</div>`;
  const done = ["done", "refunded", "abandoned"].includes(s.phase);
  $("#swap-detail").innerHTML =
    `<div class="card"><div class="row between"><h2>Swap #${s.id.slice(0, 6)}</h2>` +
    `<span class="pill ${done ? "phase-" + s.phase : "phase-active"}">${s.phase}</span></div>` +
    `<p class="muted">${s.role} · ${fmtSats(s.maker_amount_sat)} ${s.maker_chain.toUpperCase()} for ${fmtSats(s.taker_amount_sat)} ${s.taker_chain.toUpperCase()}` +
    (s.secret_revealed ? " · secret revealed" : "") + `</p>` +
    `<div class="legs">${leg("Your leg", c.maker_lock)}${leg("Counterparty", c.taker_lock)}</div>` +
    (c.refund_in_blocks != null
      ? `<p class="muted">Refund available in ${Math.max(0, c.refund_in_blocks)} blocks (if it stalls).</p>`
      : "") +
    `<p class="muted">Funds are safe: this ends claimed or refunded, always.` +
    (done ? "" : ` <span id="detail-age"></span>`) + `</p></div>`;
}

// One ticker drives the detail refresh + its countdown.
setInterval(() => {
  if (detailId === null || $("#swaps").classList.contains("active") === false) return;
  if (Date.now() >= detailNext) {
    renderSwap(detailId);
    detailNext = Date.now() + DETAIL_REFRESH * 1000;
  }
  const el = $("#detail-age");
  if (el) el.textContent = `· refreshing in ${Math.max(0, Math.round((detailNext - Date.now()) / 1000))}s`;
}, 1000);

// --- settings ---
async function loadSettings() {
  const s = await api("GET", "/settings").catch(() => null);
  if (!s) return;
  const f = $("#settings-form");
  f.btc_node.value = s.btc_node || "";
  f.xbtc_node.value = s.xbtc_node || "";
  f.relays.value = (s.relays || []).join("\n");
  f.signer.value = s.signer || "cold";
  f.btc_conf.value = s.btc_conf;
  f.xbtc_conf.value = s.xbtc_conf;
  f.margin_blocks.value = s.margin_blocks;
  f.price_reference.checked = !!s.price_reference;
  f.fee_enabled.checked = !!s.fee_enabled;
  f.fee_sp_address.value = s.fee_sp_address || "";
  if (s.fee_maker_bps != null) f.fee_maker_bps.value = s.fee_maker_bps;
  if (s.fee_taker_bps != null) f.fee_taker_bps.value = s.fee_taker_bps;
  // When StartOS owns the config (config_locked), the web view is read-only: the one source of truth
  // is the package action, and the public page never edits node or relay settings.
  const st = await api("GET", "/status").catch(() => null);
  const locked = !!(st && st.config_locked);
  [...f.elements].forEach((el) => {
    el.disabled = locked;
  });
  $("#settings-msg").textContent = locked
    ? "Node and relay settings are managed in StartOS (Actions and Config); this view is read-only."
    : "";
}
$("#settings-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  const body = {
    btc_node: f.btc_node.value.trim(),
    xbtc_node: f.xbtc_node.value.trim(),
    relays: f.relays.value.split("\n").map((x) => x.trim()).filter(Boolean),
    signer: f.signer.value,
    btc_conf: +f.btc_conf.value,
    xbtc_conf: +f.xbtc_conf.value,
    margin_blocks: +f.margin_blocks.value,
    price_reference: f.price_reference.checked,
    fee_enabled: f.fee_enabled.checked,
    fee_sp_address: f.fee_sp_address.value.trim(),
    fee_maker_bps: +f.fee_maker_bps.value,
    fee_taker_bps: +f.fee_taker_bps.value,
  };
  try {
    await api("PUT", "/settings", body);
    $("#settings-msg").textContent = "saved";
    loadStatus();
  } catch (err) {
    $("#settings-msg").textContent = (err.data && (err.data.error || (err.data.fields || []).join("; "))) || "rejected";
  }
});

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
  refresh(active);
  loadStatus();
  if (detailId !== null) detailNext = Date.now(); // a phase change refreshes the open detail at once
}

function refresh(tab) {
  if (tab === "market") loadMarket();
  else if (tab === "swaps") loadSwaps();
  else if (tab === "settings") loadSettings();
}

loadStatus();
loadMarket();
subscribe();
setInterval(loadStatus, 15000);
