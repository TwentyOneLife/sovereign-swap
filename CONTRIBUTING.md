# Contributing

Issues and pull requests are welcome.

## Licensing

This project is **dual-licensed**: the GNU Affero General Public Licence v3.0-or-later for everyone
(see `LICENSE`), and a separate **commercial licence** for organisations that need proprietary terms
(see `COMMERCIAL.md`). So the project can offer both, contributions are accepted under the Contributor
Licence Agreement in `CLA.md`: you keep your copyright and grant TwentyOne.Life the right to license
your contribution under both licences. By opening a pull request you agree to that CLA.

## Ground rules

- A change that touches the contract, signing or the replay guard comes with a test that fails
  without it. `docs/edge-cases.md` lists the scenarios a swap engine must survive; a new one gets a
  row and a test.
- Keep diffs small and readable. Comments say why, not what.
- No new dependency without a reason in the pull request, pinned exactly.

## Running the tests

Docker is the only requirement on the host.

```sh
scripts/fetch-nodes.sh /tmp/nodes > /tmp/nodes.env   # verified Bitcoin Core and Knots BLAKE2b
set -a; . /tmp/nodes.env; set +a
scripts/test-in-container.sh
```

## A note on issue numbers

Design documents may cite issue numbers from the project's own tracker, which is not public. The
reasoning that matters is written in the document itself.
