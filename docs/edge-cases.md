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
| 4 | Bad participate transaction (`test_10_bad_ptx`) | taker's invalid lock; maker must not reveal the secret and both refund | M1 (check), M2 (flow) | `check_script_names_the_wrong_field`; M2 flow test |
| 5 | Refund after timeout (`test_05_refund`, `run_test_itx_refund`) | coins come back when the other side disappears | M1 (tx), M2 (flow) | `regtest_contract_on_btc` / `_on_xbtc`: `refund_after_csv_accepted` |
| 6 | Refund too early is rejected | timelock actually enforced | M1 | `regtest_contract_on_btc` / `_on_xbtc`: `refund_before_csv_rejected` |
| 7 | Wrong preimage | only the real secret claims | M1 | `regtest_contract_on_btc` / `_on_xbtc`: `claim_wrong_preimage_rejected`; unit `claim_and_extract_preimage` |
| 8 | Hash type byte relabelled by a peer (`test_sighash_type_check.py`) | accept only SIGHASH_ALL signatures from a peer | M1 (we sign ALL only), M3 (peer signatures) | `regtest_contract_on_btc` / `_on_xbtc`: `hashtype_0x21_rejected` |
| 9 | Secret read from the counterparty's claim | taker learns the secret from the chain | M1 | `regtest_contract_on_btc` / `_on_xbtc`: `extract_preimage_from_chain`; unit `extract_preimage_ignores_refunds_and_foreign_inputs` |
| 10 | Replay of a BTC transaction on xBTC (no BasicSwap equivalent, chain-specific) | duplicated lock on the other chain | M1 | unit `replay_guard_*`, `regtest_replay_shared_coinbase` |
| 11 | Initiate lock confirms slowly (`test_05_refund_slow_itx`) | timeouts measured from confirmation, not from broadcast | M2 | |
| 12 | Claim broadcast dropped once (`test_04_ltc_btc_dropped_redeems`) | rebroadcast until confirmed | M2 | |
| 13 | Claim reorged out (`test_04_ltc_btc_redeem_reorg`) | watch confirmations, rebroadcast after reorg | M2 | |
| 14 | Self bid (`test_06_self_bid`) | refuse trading with oneself | M2 | |
| 15 | Variable amount bids (`test_15_variable_amount`) | amounts and rounding | M2 | |
| 16 | Restart in any state (`test_reload.py`, `test_persistent.py`) | no missed deadline after a crash | M2 | |
| 17 | Proof of funds (`test_proof_of_funds.py`) | bids backed by real coins | M3 | |
| 18 | Error state handling (`test_07_error`) | a failed step ends in a safe state | M2 | |
| 19 | Lock output index (`test_012_lock_tx_vout`) | lock found at any output position | M1 | `find_lock_output_checks_amount_and_index` |
| 20 | Transaction size and fee (`test_010_txn_size`) | claim and refund pay a sufficient fee | M2 | |
