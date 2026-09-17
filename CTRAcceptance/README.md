# AES128CTR acceptance

Proves the ported cipher against a real OpenSSH rather than against ourselves.
Requires macOS's `/usr/sbin/sshd`; runs as your own user, no root, listening on
127.0.0.1 only, with a throwaway key generated per run.

    ./run.sh

It stands up five sshd instances covering both ciphers and three rekey
policies, checks that the CTR endpoint really does refuse a GCM client, then
runs:

- `ctrtest` — the acceptance list once: command round trip, 4 MB bulk stream,
  checksummed stream, the same an order of magnitude larger, SFTP round trip.
  It does not test rekeying; that is the `IDLE` run below.
- `rekeyprobe` — one connection, N checksummed reads, each under a 45s
  watchdog, so a stall is reported per iteration instead of hanging the run.
  Env: `CTR_PORT`, `BYTES`, `ITERATIONS`, `IDLE`, `LABEL`.

`ctrtest` is retried up to three times, because Citadel stalls on a large
`executeCommand` roughly half the time for reasons unrelated to this cipher.
Corruption is never retried. Exit code is 0 only if the acceptance list
completed and a real rekey was observed.

Read the results with one distinction in mind: **corrupt** implicates the
cipher, **stalled** does not. Stalls reproduce identically on `aes128-gcm` and
on `volpy/nio-ssh-0.9.1` with no CTR code compiled in — see
`docs/citadel-large-output-stall.md` in the Halyard repo.
