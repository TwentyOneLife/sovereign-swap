# Roadmap

What is coming to Sovereign Swap, in rough order. This is a direction, not a schedule: there are no dates
here and no promises on timing. Items can move, change shape, or ship in pieces, and anything
safety-critical waits until it has been proven end to end.

Today the software works as the rest of this guide describes: self-hosted, non-custodial, and peer to
peer. What follows mostly makes it easier to run safely, easier to verify, and easier to reach without
running your own node.

## In rough order

- **QR codes for air-gapped funding and signing.** Show a funding or claim transaction as a QR in the app
  itself, so a hardware signer such as a SeedSigner can scan it, sign offline, and hand the signature back
  by QR, with no cable and no spending key ever on a connected machine.

- **SPV proofs for a swap's on-chain locks.** Carry a compact proof that each lock really confirmed on its
  chain, so the other side (or a light client) can check the swap independently, without trusting a full
  node to report the chain honestly.

- **User-held claim and refund signing.** Move the keys and the signing for a swap's claim and refund
  fully into your own browser or wallet, so even a node you connect to never holds the key that settles
  your side.

- **An anonymised protocol fee by default.** The fee can already pay a silent-payment address, so the
  project's fee receipts are not all tied to one reused address on chain (see
  [Set a silent-payment fee address](/guides/fee-silent-payment-address)). The direction here is to make a
  silent-payment fee the standard path rather than something each operator sets up by hand.

- **A hosted, non-custodial service.** A way to swap without running a full node and without an account,
  at [swap.twentyone.life](https://twentyone.life/swap), coming soon. It stays non-custodial: your keys
  and your signing remain yours, on the user-held path above.

- **Broader real-value go-live validations.** More end-to-end swaps carrying real value on both chains, to
  shake out the last edge cases, before the service is opened up more widely.

## No commitments

None of the above is a commitment. Order and scope can change. For what has actually shipped, follow the
[GitHub repository](https://github.com/TwentyOneLife/sovereign-swap).
