# Contributing

Issues and pull requests are welcome. Everything here is AGPL-3.0-or-later, and contributions are
accepted under that licence.

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
