# Edge cases, re-engineered from BasicSwap

BasicSwap (MIT, https://github.com/basicswap/basicswap, read at v0.19.1) has run secret-hash swaps
between Bitcoin-family chains since 2020. Its tests and failure paths are the specification of what a
swap engine must survive. Each row is a scenario we cover with a test of our own; a milestone is not
done while one of its rows lacks a passing test.

| # | Scenario (BasicSwap source) | What it protects | Milestone | Our test (scenario label inside the test) |
|---|---|---|---|---|
| 1 | Preimage size fixed at 32 bytes (`atomic_swap_1.buildContractScript`, `OP_SIZE`) | secret usable on both chains; on xBTC mainnet RDTS rejects items above 256 bytes (regtest does not enforce RDTS, so the test proves the `OP_SIZE` check) | M1 | `regtest_contract_on_btc` / `_on_xbtc`: `oversized_preimage_33/300_rejected_by_consensus` |
| 2 | Counterparty script checked against the exact template (`verifyContractScript`) | a lock that looks right but pays elsewhere or uses another hash or timeout | M1 | `check_script_names_the_wrong_field`, `from_script_rejects_anything_but_the_template` |
| 3 | Wrong lock amount (`test_11_bad_itx`, "Incorrect output amount in initiate txn") | under-funded lock | M1 (check), M2 (stop the swap) | `find_lock_output_checks_amount_and_index` |
| 4 | Bad participate transaction (`test_10_bad_ptx`) | taker's invalid lock; maker must not reveal the secret and both refund | M1 (check), M2 (flow) | `check_script_names_the_wrong_field`; unit `maker_claims_only_a_deep_correct_lock_with_time_left` (wrong amount); two-engine test with a malicious counterparty: open |
| 5 | Refund after timeout (`test_05_refund`, `run_test_itx_refund`) | coins come back when the other side disappears | M1 (tx), M2 (flow) | `regtest_contract_on_btc` / `_on_xbtc`: `refund_after_csv_accepted`; two engines: `maker_refunds_when_the_taker_never_locks`, `both_refund_when_the_maker_never_claims` |
| 6 | Refund too early is rejected | timelock actually enforced | M1 | `regtest_contract_on_btc` / `_on_xbtc`: `refund_before_csv_rejected` |
| 7 | Wrong preimage | only the real secret claims | M1 | `regtest_contract_on_btc` / `_on_xbtc`: `claim_wrong_preimage_rejected`; unit `claim_and_extract_preimage` |
| 8 | Hash type byte relabelled by a peer (`test_sighash_type_check.py`) | accept only SIGHASH_ALL signatures from a peer | M1 (we sign ALL only), M3 (peer signatures) | `regtest_contract_on_btc` / `_on_xbtc`: `hashtype_0x21_rejected` |
| 9 | Secret read from the counterparty's claim | taker learns the secret from the chain | M1 | `regtest_contract_on_btc` / `_on_xbtc`: `extract_preimage_from_chain`; unit `extract_preimage_ignores_refunds_and_foreign_inputs` |
| 10 | Replay of a BTC transaction on xBTC (no BasicSwap equivalent, chain-specific) | duplicated lock on the other chain | M1, M2 (wired) | unit `replay_guard_*`, `regtest_replay_shared_coinbase`, `engine_refuses_to_lock_coins_that_exist_on_both_chains` |
| 11 | Initiate lock confirms slowly (`test_05_refund_slow_itx`) | timeouts measured from confirmation; the taker locks only while enough of the maker's lock remains | M2 | unit `taker_refuses_a_late_maker_lock`, `taker_does_not_abandon_a_lock_it_has_funded`; two-engine variant: open |
| 12 | Claim broadcast dropped once (`test_04_ltc_btc_dropped_redeems`) | rebroadcast until confirmed | M2 | `swap_completes_when_the_first_claim_is_dropped`; unit `maker_keeps_claiming_once_the_secret_is_out` |
| 13 | Claim reorged out (`test_04_ltc_btc_redeem_reorg`) | watch confirmations, rebroadcast after reorg | M2 | unit `a_reorged_claim_is_claimed_again_with_the_kept_secret`, `maker_funds_once_then_waits` (lock reorged away); chain-level reorg test: open |
| 14 | Self bid (`test_06_self_bid`) | refuse trading with oneself | M2 | `an_engine_does_not_bid_on_its_own_offer` |
| 15 | Variable amount bids (`test_15_variable_amount`) | amounts and rounding | M2 | unit `taker_part_rounds_down_and_refuses_small_or_large_bids`; partial-bid swap on chain: open |
| 16 | Restart in any state (`test_reload.py`, `test_persistent.py`) | no missed deadline after a crash | M2 | `swap_survives_a_restart_after_every_step` |
| 17 | Proof of funds (`test_proof_of_funds.py`) | bids backed by real coins | M3 | |
| 18 | Error state handling (`test_07_error`) | a failed step ends in a safe state | M2 | `engine_refuses_to_lock_coins_that_exist_on_both_chains` (refused funding leaves the swap in `Locking`, nothing broadcast); unit `taker_refuses_a_wrong_amount_and_gives_up_after_the_deadline` |
| 19 | Lock output index (`test_012_lock_tx_vout`) | lock found at any output position | M1 | `find_lock_output_checks_amount_and_index` |
| 20 | Transaction size and fee (`test_010_txn_size`) | claim and refund pay a sufficient fee | M2 | |
