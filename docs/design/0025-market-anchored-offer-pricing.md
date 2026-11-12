# 0025 Market-anchored offer pricing: the nonkyc rate is the default, the maker sets the margin

Status: design, proposed 2026-11-12. Not yet implemented. Depends on the price reference actually
resolving (the relay price proxy, #106, and its live failure #207). Relates to the large-rate display
work (#89) and the voluntary fee (0010/0013/0018). Tracked in a new issue.

## Context: the price is an economic decision, and today nothing anchors it

A swap offer prices one chain's coin against the other: when the maker sells BTC, the offer's price is
`counter_amount_sat / amount_sat` = **xBTC per BTC**. BTC (SHA256) and BTC-Blake2b (xBTC) are different
assets with very different value, so this price is far from 1.0 (recent real offers sat near ~270 xBTC
per BTC; the inverse, BTC per xBTC, is ~0.0037).

There is a real external reference for this pair: the **nonkyc `BTCB2_BTC` ticker**
(`relay_price.rs`, `reference_rate`), `rate` = BTC per xBTC. Because nonkyc blocks many Tor exits, the
relay fetches it over clearnet and serves it to clients over Tor (the price proxy, #106); a client may
also try direct. The current UI surfaces this only as a header status dot, and the Create-offer form
derives price context from *our own order book* ("xBTC has no liquid market" - `app.js`), not the
external rate.

Offer pricing accepts either:
- `price` (a float), band-checked against the **absolute** `MIN_PRICE=0.5 .. MAX_PRICE=2.0`; or
- `counter_amount_sat` (an integer), for which **the band check is deliberately skipped** and the
  amount is taken verbatim.

For a lopsided pair, `price`'s 0.5-2.0 band is meaningless (a real price of ~270 is nowhere near it), so
every real offer uses `counter_amount_sat`, which has **no market anchoring at all**. An offer of
`amount_sat=5000, counter_amount_sat=5000` (a 1:1 rate, off market by ~270x) publishes without a single
guard rail. That hole is not hypothetical: an automated run posted exactly that offer. The point of
this note is to close it.

## Principle: the market sets the default, a human sets the spread, automation sets neither

1. **The nonkyc `BTCB2_BTC` rate is the default and the anchor.** An offer's price defaults to the live
   reference rate. No offer is priced from thin air or from a fixed ratio.
2. **The effective rate is always displayed** - the market rate, the maker's spread, and the resulting
   price and counter amount - so a maker always sees what they are offering relative to the market.
3. **Only the human maker may move off the market rate**, by a bounded margin, to earn more or less as a
   maker. This is a deliberate UI action with the number in front of them.
4. **An automated / non-interactive caller may not invent a rate.** The API must not accept an
   off-market price from a script: without an explicit, in-band human margin, the only rate is the
   market rate. A raw `counter_amount_sat` that implies an off-market price is rejected, not taken
   verbatim.

## Decision

### D1. Reference rate is a hard input to pricing, not just a status dot
`post_offer` (publish) and the take-side pre-check gain access to the current reference rate (same
source as `/reference-rate`: relay proxy first, direct second). The rate carries an `as_of`; a rate
older than `REFERENCE_MAX_AGE` (proposed 15 min) is treated as absent.

### D2. The offer price defaults to the market rate
The Create-offer form, on open, fetches the reference and pre-fills the price at the market rate for the
chosen direction, and computes `counter_amount_sat` from it. The maker never has to hand-type a
counter amount to be on-market.

### D3. A margin, set only by the human maker, in whole-percent (1%) steps
Add a maker **margin in whole percent** (`margin_pct`, a signed integer: positive earns the maker more,
i.e. asks for more of the counter coin than the market; negative undercuts the market to fill faster).
The effective price = `market_price * (1 + margin_pct/100)`. The UI stepper moves in **1% steps**; the
value is an integer percent (no fractional percents, no continuous slider). The default is `0` (exactly
the market). There is **no fixed `+-10%` clamp**; how far off-market an offer may sit is governed solely
by the band in D4, which is an **operator setting, not a hardcoded constant**. `counter_amount_sat` is
derived from the effective price; integer rounding favours the maker by at most one sat and is shown.

### D4. The price band becomes RELATIVE to the market rate, replacing the absolute 0.5-2.0
An offer is in band iff its implied price is within the operator-configured `price_band_pct` of the
current market rate, in either direction (a `Settings` field, default proposed 10%, expressed in whole
percent to match the D3 step; **not** a compiled-in constant). The absolute `MIN_PRICE`/`MAX_PRICE`
constants are **deleted** (dead after this change - they were only meaningful for a parity pair; the
"remove unused hardcoded values" requirement). A `price` or a `counter_amount_sat` that implies an
out-of-band rate is **rejected at publish** with the market rate and the allowed range in the error. The
check also runs take-side before a taker commits (it is the maker's published price the taker is about
to act on), mirroring the F3 fee-band pattern: **enforced locally at publish and at take, never in
counterparty verification**, so no wire-format change and no new-vs-old peer disagreement.

### D5. `counter_amount_sat` is retained only as a derived, in-band value
The API still accepts `counter_amount_sat` (lopsided integers are needed and a float price cannot
express ~270 precisely, #89), but it is now **validated against the band in D4** instead of skipping
it. A direct `counter_amount_sat` that lands outside the band is refused, so the verbatim-bypass hole is
closed. The GUI always sends `counter_amount_sat` derived from `market_price` and `margin_pct`.

### D6. No reference, no off-market offer
If the reference is absent or stale (D1), the default price cannot be computed. In that state:
- The GUI disables the price field's market pre-fill and shows "market rate unavailable"; it will not
  invent a rate.
- Publish **rejects** an offer whose price is not demonstrably on-market, unless the operator has set an
  explicit `allow_unreferenced_pricing` escape (off by default, operator-only, logged), for the degraded
  case where the reference is down but a human still wants to trade on a hand-entered price. Automation
  never gets this escape.

This makes the reference a release dependency: #207 (relay price proxy failing live) must be fixed for
market-anchored pricing to function, otherwise every offer needs the manual escape.

## Display (D2/D3 surfaced)

The Create-offer form shows, live as the maker types the amount or drags the margin:
- the market rate both ways ("1 BTC = N xBTC  /  1 xBTC = M BTC", from nonkyc, with `as_of` age),
- the maker's `margin_pct` control (a 1% stepper, default 0, bounded only by `price_band_pct`),
- the **effective price** and the resulting `counter_amount_sat`,
- a plain-language profit line ("you receive ~X% more/less than market as the maker"),
- a stale/unavailable banner when D6 applies.

The two-asset reminder stays: this is BTC-Blake2b, a different asset from Bitcoin.

## What this is NOT

- Not an oracle for settlement: the rate only prices the *offer*. Once taken, amounts are fixed on both
  locks as today.
- Not a protocol change: all new checks are local (publish + pre-take), like the F3 fee band. The
  on-chain and Nostr formats are unchanged; an old peer still verifies amounts, never a rate.
- Not automation-adjustable: the margin is a human-only control. A headless caller gets the market rate
  or a rejection, never a free-form rate.

## Edge cases

- **Reference stale/down:** D6 (reject or operator escape). Never silently fall back to 1.0 or to the
  order-book midpoint as a *default* price.
- **Extreme spread (bid/ask wide):** price off `rate` (last trade); optionally warn if `rate` sits
  outside `[bid, ask]` by more than the band.
- **Rounding at tiny amounts:** show the exact derived `counter_amount_sat`; the 1-sat maker-favourable
  rounding is disclosed, not hidden.
- **Pair delisted / ticker shape change:** parse failure is "reference unavailable" (D6), not a zero.

## Implementation sketch (for the tracking issue)

1. `fee.rs`-style pricing module: `effective_price(market, margin_pct)`, `in_band(price, market, band_pct)`,
   `counter_from(amount_sat, price)`, with the caps/age constants.
2. `NewOffer`: add `margin_pct: Option<i32>` (human margin, whole percent); keep `price`/`counter_amount_sat`; validate
   all three against the band using the reference the daemon already fetches.
3. `post_offer` + the take pre-check: pull the current reference (reuse `reference_rate`'s path), apply
   D4/D5/D6.
4. GUI Create-offer: fetch reference on open, pre-fill, margin control, live effective-rate + profit
   display, derive `counter_amount_sat`, D6 banner.
5. Remove the absolute `MIN_PRICE/MAX_PRICE` from the publish path; keep a sanity ceiling only as a
   guard against a garbage reference.
6. Ride on #207 being fixed first (relay price proxy delivering over Tor); add a regression test that an
   off-market `counter_amount_sat` (e.g. 1:1) is rejected at publish.
