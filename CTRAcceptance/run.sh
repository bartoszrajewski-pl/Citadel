#!/bin/bash
# Stands up local OpenSSH servers and runs the AES128CTR acceptance list.
# Needs no root and touches nothing outside its own directory.
set -euo pipefail
cd "$(dirname "$0")"
RUN=${RUN_DIR:-$(mktemp -d /tmp/ctr-acceptance.XXXXXX)}
mkdir -p "$RUN"

cleanup() {
  for f in "$RUN"/sshd_*.pid; do
    [ -f "$f" ] || continue
    kill "$(cat "$f")" 2>/dev/null || true
  done
  for p in $(jobs -p); do kill "$p" 2>/dev/null || true; done
  return 0
}
trap cleanup EXIT

# Set to 1 by any genuine failure; the script's exit code, so a caller can
# trust it. It used to be whatever the cleanup trap's last kill returned.
STATUS=0

if [ ! -f "$RUN/clientkey" ]; then
  ssh-keygen -q -t ed25519 -N '' -f "$RUN/hostkey"   -C ctr-acceptance-host
  ssh-keygen -q -t ed25519 -N '' -f "$RUN/clientkey" -C ctr-acceptance-client
  cp "$RUN/clientkey.pub" "$RUN/authorized_keys"
  chmod 600 "$RUN/authorized_keys"
fi

# port : cipher : rekey policy.  An array read with IFS, because two of the
# rekey policies contain a space and word-splitting silently produced servers
# named "30" and "none" the first time this was written.
CONFIGS=(
  "62203:aes128-ctr:256K"
  "62204:aes128-gcm@openssh.com:256K"
  "62205:aes128-ctr:default none"
  "62206:aes128-gcm@openssh.com:default none"
  "62207:aes128-ctr:1G 30"
)

for cfg in "${CONFIGS[@]}"; do
  IFS=: read -r port cipher rekey <<< "$cfg"
  cat > "$RUN/sshd_$port.conf" <<EOF
Port $port
ListenAddress 127.0.0.1
HostKey $RUN/hostkey
PidFile $RUN/sshd_$port.pid
StrictModes no
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile $RUN/authorized_keys
Ciphers $cipher
MACs hmac-sha2-256
RekeyLimit $rekey
PrintMotd no
PrintLastLog no
Subsystem sftp /usr/libexec/sftp-server
EOF
  /usr/sbin/sshd -f "$RUN/sshd_$port.conf" -D -e -o LogLevel=DEBUG1 > "$RUN/sshd_$port.log" 2>&1 &
done
sleep 1

# The endpoint must refuse a GCM-only client, or "it negotiated CTR" proves
# nothing about which cipher actually ran.
if ssh -p 62203 -i "$RUN/clientkey" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
       -o UserKnownHostsFile=/dev/null -o Ciphers=aes128-gcm@openssh.com \
       "$(whoami)@127.0.0.1" true 2>/dev/null; then
  echo "FAIL: 62203 accepted a GCM client; it is not CTR-only"; exit 1
fi
echo "62203 is CTR-only (a GCM client is refused)"

if ! swift build > "$RUN/build.log" 2>&1; then
  grep "error:" "$RUN/build.log" | head || true
  echo "FAIL: build"; exit 1
fi
tail -1 "$RUN/build.log"

export CTR_KEY="$RUN/clientkey"
echo
echo "=== full acceptance list, aes128-ctr, rekeying off ==="
# Citadel stalls on a large executeCommand roughly half the time, with no rekey
# involved and on GCM just the same (see the matrix below). That is not this
# cipher's bug, so retry through it rather than reporting a red list because of
# someone else's race. Corruption is never retried — that would be ours.
attempt=1
while [ $attempt -le 3 ]; do
  if timeout 180 ./.build/debug/ctrtest > "$RUN/ctrtest.log" 2>&1; then
    grep -E "^\[" "$RUN/ctrtest.log"
    [ $attempt -gt 1 ] && echo "(completed on attempt $attempt; earlier ones hit Citadel's stall)"
    break
  fi
  if grep -q "FAIL" "$RUN/ctrtest.log"; then
    grep -E "^\[|FAIL" "$RUN/ctrtest.log"
    echo "CIPHER FAILURE: a checksum did not match. This one is ours."
    STATUS=1
    break
  fi
  grep -E "^\[" "$RUN/ctrtest.log" || true
  echo "  attempt $attempt stalled after the line above (Citadel's large-output bug)"
  attempt=$((attempt + 1))
  if [ $attempt -gt 3 ]; then
    echo "INCOMPLETE: stalled on all 3 attempts. Not corruption — but the list did not finish."
    STATUS=1
  fi
done

echo
echo "=== rekey on an idle timer: updateKeys under a real OpenSSH ==="
CTR_PORT=62207 LABEL=idle-rekey IDLE=45 BYTES=200000 ITERATIONS=3 timeout 300 ./.build/debug/rekeyprobe 2>&1 | grep -E "^idle-rekey"
# Without this the check passes vacuously when the server never rekeys, which
# is exactly what a mis-split config did once.
updates=$(grep -c "ssh_set_newkeys: rekeying out" "$RUN/sshd_62207.log" || true)
echo "server-side key updates during that connection: $updates"
if [ "$updates" -lt 1 ]; then
  echo "FAIL: no rekey happened, so the transfers above prove nothing about updateKeys"; exit 1
fi
echo
echo "=== stall matrix (this is Citadel's bug, not the cipher's) ==="
for port in 62205 62206 62203 62204; do
  cipher=$(grep '^Ciphers' "$RUN/sshd_$port.conf" | awk '{print $2}')
  rekey=$(grep '^RekeyLimit' "$RUN/sshd_$port.conf" | cut -d' ' -f2-)
  printf '%-24s rekey=%-14s ' "$cipher" "$rekey"
  CTR_PORT=$port LABEL=m ITERATIONS=4 timeout 400 ./.build/debug/rekeyprobe 2>&1 | grep RESULT || echo "RESULT (probe itself timed out)"
done
echo
echo "logs and keys: $RUN"
exit $STATUS
