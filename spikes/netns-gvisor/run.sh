#!/usr/bin/env bash
# Spike: can an enforcer container own a session's network namespace, with
# the agent runtime joining it (--network container:<enforcer>) under each
# container runtime, so that nftables rules in that namespace (a) allow the
# gateway, (b) block and log everything else, and (c) cannot be changed from
# inside the runtime?
#
# Run inside the VM:  scripts/vm.sh shell sudo spikes/netns-gvisor/run.sh
set -uo pipefail
P=fgspike
NET=$P-net
SUBNET=172.31.250.0/24
GW_IP=172.31.250.10
SINK_IP=172.31.250.20

cleanup() {
  docker rm -f $(docker ps -aq --filter label=$P) >/dev/null 2>&1 || true
  docker network rm $NET >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

# Kernel only logs netfilter events from non-initial namespaces when asked.
sysctl -qw net.netfilter.nf_log_all_netns=1

docker build -q -t $P-enforcer - >/dev/null <<'EOF'
FROM alpine:3.20
RUN apk add --no-cache nftables
EOF
docker build -q -t $P-tools - >/dev/null <<'EOF'
FROM alpine:3.20
RUN apk add --no-cache curl python3 nftables iproute2
EOF

docker network create --internal --subnet $SUBNET --label $P $NET >/dev/null
docker run -d --label $P --name $P-gw   --network $NET --ip $GW_IP   $P-tools python3 -m http.server 8443 >/dev/null
docker run -d --label $P --name $P-sink --network $NET --ip $SINK_IP $P-tools python3 -m http.server 8080 >/dev/null

RESULTS=()
record() { RESULTS+=("$(printf '%-16s %-34s %s' "$1" "$2" "$3")"); }

for RT in runc runsc-kernelnet; do
  E=$P-enf-$RT
  docker run -d --label $P --name $E --network $NET --cap-drop ALL --cap-add NET_ADMIN \
    $P-enforcer sleep infinity >/dev/null
  docker exec -i $E nft -f - <<EOF
table inet fg {
  chain out {
    type filter hook output priority 0; policy drop;
    oif lo accept
    ct state established,related accept
    ip daddr $GW_IP tcp dport 8443 accept
    log prefix "FG-DROP sess=$RT " level warn
  }
}
EOF
  if ! docker exec $E nft list table inet fg >/dev/null 2>&1; then
    echo "FATAL: rules not loaded in $E" >&2; exit 1
  fi

  run_in() {  # run a command in a runtime container that shares the enforcer's netns
    timeout 60 docker run --rm --label $P --runtime $RT --network container:$E \
      --cap-drop ALL --security-opt no-new-privileges --read-only --user 65534:65534 \
      $P-tools sh -c "$1" 2>&1
  }

  out=$(run_in "curl -s -m 5 -o /dev/null -w '%{http_code}' http://$GW_IP:8443/")
  record $RT "gateway reachable (want 200)" "$out"

  before=$(journalctl -k --no-pager | grep -c "FG-DROP sess=$RT ")
  out=$(run_in "curl -s -m 5 -o /dev/null -w '%{http_code}' http://$SINK_IP:8080/?c=CANARY || echo BLOCKED")
  record $RT "sink blocked (want BLOCKED)" "$out"
  out=$(run_in "curl -s -m 5 -o /dev/null -w '%{http_code}' http://1.1.1.1/ || echo BLOCKED")
  record $RT "raw IP blocked (want BLOCKED)" "$out"
  sleep 1
  after=$(journalctl -k --no-pager | grep -c "FG-DROP sess=$RT ")
  record $RT "drops logged by VM kernel" "$((after - before)) new log lines"

  # Root inside the runtime, still without capabilities, tries to remove the rules.
  out=$(timeout 60 docker run --rm --label $P --runtime $RT --network container:$E --cap-drop ALL \
    $P-tools sh -c 'nft flush ruleset 2>&1; echo rc=$?' | tail -2 | tr '\n' ' ')
  record $RT "flush rules as root (want fail)" "$out"
  out=$(run_in "curl -s -m 5 -o /dev/null -w '%{http_code}' http://$SINK_IP:8080/ || echo BLOCKED")
  record $RT "sink still blocked after flush" "$out"

  docker rm -f $E >/dev/null
done

echo
printf '%-16s %-34s %s\n' RUNTIME CHECK RESULT
printf '%s\n' "${RESULTS[@]}"
echo
echo "Sink access log (anything here reached the sink):"
docker logs $P-sink 2>&1 | grep -v "Serving HTTP" || echo "  (empty)"
