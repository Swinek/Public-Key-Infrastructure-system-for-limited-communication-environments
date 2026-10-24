#!/usr/bin/env bash
# "Łączność" from the architecture diagram: decides which edge client has the WAN link (internet on/off)
# and which pairs of edge clients are in radio range (link up/down). Also starts the edge nodes:
# client_N = Edge client N (edge_client/node), app_N = Edge app N (edge_app).

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.edge.yml"
CLIENTS=("client_1" "client_2" "client_3")
INTERNET_NET="internet_net"
# Radio links: one Docker network per link, p2p_<a><b> (a < b) connects client_a and client_b.
# p2p_12 and p2p_23 come from docker-compose.edge.yml; any other pair is created on demand by `link up`
# (labelled P2P_LABEL, removed by `down`).
P2P_LABEL="pki.edge.p2p-link=dynamic"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

ensure_networks() {
    docker network inspect "$INTERNET_NET" >/dev/null 2>&1 || docker network create "$INTERNET_NET" >/dev/null 2>&1 || true
}

is_container_running() {
    local name="$1"
    [ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null)" = "true" ]
}

is_connected() {
    local name="$1"
    local net="$2"
    docker inspect "$name" --format '{{json .NetworkSettings.Networks}}' 2>/dev/null | grep -q "\"$net\""
}

has_internet_access() {
    is_connected "$1" "$INTERNET_NET"
}

# 1 | client1 | client_1 -> client_1 (works for any N)
get_client_container() {
    local target="$1"
    if [[ "$target" =~ ^[0-9]+$ ]]; then
        echo "client_$target"
    elif [[ "$target" =~ ^client([0-9]+)$ ]]; then
        echo "client_${BASH_REMATCH[1]}"
    else
        echo "$target"
    fi
}

is_known_client() {
    local name="$1"
    local c
    for c in "${CLIENTS[@]}"; do
        [ "$c" = "$name" ] && return 0
    done
    return 1
}

client_number() {
    echo "${1#client_}"
}

# Prints target containers (one per line): "all"/empty -> every client, otherwise a single validated client.
resolve_targets() {
    local target="$1"
    if [ "$target" = "all" ] || [ -z "$target" ]; then
        printf '%s\n' "${CLIENTS[@]}"
        return 0
    fi
    local client
    client=$(get_client_container "$target")
    if ! is_known_client "$client"; then
        echo -e "${RED}[ERROR] Unknown client: '$target'. Available: 1, 2, 3, client_1..client_3, all${NC}" >&2
        return 1
    fi
    echo "$client"
}

require_client() {
    local client
    client=$(get_client_container "$1")
    if [ -z "$1" ] || ! is_known_client "$client"; then
        echo -e "${RED}[ERROR] Unknown client: '$1'. Available: 1, 2, 3${NC}" >&2
        exit 1
    fi
    echo "$client"
}

set_internet() {
    local action="$1"
    local target="$2"

    ensure_networks

    local targets
    targets=$(resolve_targets "$target") || exit 1

    for client in $targets; do
        if ! is_container_running "$client"; then
            echo -e "${YELLOW}[!] Container $client is not running. Start first: ./client.sh up${NC}"
            continue
        fi

        if [ "$action" = "on" ]; then
            if has_internet_access "$client"; then
                echo -e "${CYAN}[i] $client: Internet is ALREADY enabled (ONLINE).${NC}"
            else
                # Alias inet-<id> resolves only via internet_net (used by /api/internet/test).
                docker network connect --alias "inet-$client" "$INTERNET_NET" "$client"
                echo -e "${GREEN}[+] $client: Internet access ENABLED (ONLINE).${NC}"
            fi
            # Contact with the portal: the node starts its WAN exchanges (also on a repeated `internet on`).
            docker exec "$client" curl -s -X POST http://localhost:8000/api/contact/wan >/dev/null || true
        elif [ "$action" = "off" ]; then
            if has_internet_access "$client"; then
                docker network disconnect "$INTERNET_NET" "$client"
                echo -e "${YELLOW}[-] $client: Internet access DISABLED (OFFLINE).${NC}"
            else
                echo -e "${CYAN}[i] $client: Internet is ALREADY disabled (OFFLINE).${NC}"
            fi
        fi
    done
}

# Static IP of a client in a P2P network, read from docker-compose.yml (fallback: 192.168.<ab>.<N>0 scheme).
link_ip() {
    local client="$1"
    local net="$2"
    local ip
    ip=$(docker compose -f "$COMPOSE_FILE" config --format json 2>/dev/null | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    print(d["services"][sys.argv[1]]["networks"][sys.argv[2]]["ipv4_address"])
except Exception:
    pass
' "$client" "$net")
    if [ -z "$ip" ]; then
        ip="192.168.${net#p2p_}.$(client_number "$client")0"
    fi
    echo "$ip"
}

set_link() {
    local action="$1"
    local a b
    a=$(require_client "$2")
    b=$(require_client "$3")
    local na nb
    na=$(client_number "$a")
    nb=$(client_number "$b")
    local net
    if [ "$na" -eq "$nb" ]; then
        echo -e "${RED}[ERROR] A radio link needs two different nodes.${NC}"
        exit 1
    fi
    if [ "$na" -lt "$nb" ]; then net="p2p_${na}${nb}"; else net="p2p_${nb}${na}"; fi

    if ! docker network inspect "$net" >/dev/null 2>&1; then
        if [ "$action" = "down" ]; then
            echo -e "${CYAN}[i] Radio link $a <-> $b does not exist (already DOWN).${NC}"
            return 0
        fi
        # New pair in radio range: create the link network (same addressing scheme as compose).
        docker network create --driver bridge --internal --label "$P2P_LABEL" \
            --subnet "192.168.${net#p2p_}.0/24" "$net" >/dev/null
        echo -e "${GREEN}[+] Created radio link network $net (192.168.${net#p2p_}.0/24).${NC}"
    fi

    for client in "$a" "$b"; do
        if ! is_container_running "$client"; then
            echo -e "${YELLOW}[!] Container $client is not running.${NC}"
            continue
        fi
        if [ "$action" = "down" ]; then
            if is_connected "$client" "$net"; then
                docker network disconnect "$net" "$client"
                echo -e "${YELLOW}[-] $client disconnected from $net.${NC}"
            else
                echo -e "${CYAN}[i] $client is ALREADY disconnected from $net.${NC}"
            fi
        else
            if is_connected "$client" "$net"; then
                echo -e "${CYAN}[i] $client is ALREADY connected to $net.${NC}"
            else
                local ip
                ip=$(link_ip "$client" "$net")
                docker network connect --ip "$ip" "$net" "$client"
                echo -e "${GREEN}[+] $client connected to $net ($ip).${NC}"
            fi
        fi
    done

    if [ "$action" = "down" ]; then
        echo -e "${YELLOW}[-] Radio link $a <-> $b is DOWN.${NC}"
    else
        # Link established: node a sends ONE hello on this link only, node b answers with one hello-ack.
        # Each of them then exchanges data with the other exactly once (contact.py); other links are unchanged.
        is_container_running "$a" && \
            docker exec "$a" curl -s -X POST "http://localhost:8000/api/neighbours/discover?network=192.168.${net#p2p_}.0/24" >/dev/null || true
        echo -e "${GREEN}[+] Radio link $a <-> $b is UP (neighbours greeted).${NC}"
    fi
}

p2p_networks() {
    docker network ls --format '{{.Name}}' | grep -E '^p2p_[0-9]+$' | sort || true
}

show_links() {
    echo -e "\n${BLUE}=== RADIO LINKS (P2P networks) ===${NC}"
    local nets
    nets=$(p2p_networks)
    if [ -z "$nets" ]; then
        echo -e "  ${YELLOW}no radio links${NC}"
    fi
    for net in $nets; do
        local members
        members=$(docker network inspect "$net" -f '{{range .Containers}}{{.Name}}({{.IPv4Address}}) {{end}}')
        echo -e "  ${CYAN}$net${NC}: ${members:-<link down>}"
    done
    echo ""
}

run_endpoint() {
    local endpoint="$1"
    local target="$2"
    local targets
    targets=$(resolve_targets "$target") || exit 1

    for client in $targets; do
        if ! is_container_running "$client"; then
            echo -e "${RED}[!] Container $client is not running.${NC}"
            continue
        fi
        echo -e "\n${BLUE}============================================================${NC}"
        echo -e "  ENDPOINT: ${MAGENTA}GET $endpoint${NC} on ${CYAN}$client${NC}"
        echo -e "${BLUE}------------------------------------------------------------${NC}"
        docker exec "$client" curl -s "http://localhost:8000$endpoint" | python3 -m json.tool || true
    done
    echo ""
}

# msg <from> <to> "text"  (or legacy: msg <from> "text" when the node has a single neighbour)
send_p2p_message() {
    local sender recipient msg
    sender=$(require_client "$1")
    if [ $# -ge 3 ]; then
        recipient=$(require_client "$2")
        msg="$3"
    else
        recipient=""
        msg="$2"
    fi

    if [ -z "$msg" ]; then
        echo -e "${RED}[ERROR] Provide message content. Usage: ./client.sh msg 1 3 \"Message text\"${NC}"
        exit 1
    fi

    local body
    body=$(python3 -c 'import json, sys; d = {"message": sys.argv[1]}; d.update({"to": sys.argv[2]} if sys.argv[2] else {}); print(json.dumps(d))' "$msg" "$recipient")

    echo -e "${BLUE}[*] Sending message from $sender to ${recipient:-<default peer>}...${NC}"
    echo "$body" | docker exec -i "$sender" curl -s -X POST http://localhost:8000/api/p2p/send-message \
        -H "Content-Type: application/json" \
        --data-binary @- | python3 -m json.tool
}

show_inbox() {
    local client
    client=$(require_client "${1:-2}")

    echo -e "\n${BLUE}=== P2P INBOX FOR $client ===${NC}"
    docker exec "$client" curl -s http://localhost:8000/api/p2p/inbox | python3 -m json.tool
    echo ""
}

# send-file <from> <to> <file>  (or legacy: send-file <from> <file>)
send_file_p2p() {
    local sender recipient filepath
    sender=$(require_client "$1")
    if [ $# -ge 3 ]; then
        recipient=$(require_client "$2")
        filepath="$3"
    else
        recipient=""
        filepath="$2"
    fi

    if [ ! -f "$filepath" ]; then
        echo -e "${RED}[ERROR] File '$filepath' does not exist on disk.${NC}"
        exit 1
    fi

    local filename
    filename=$(basename "$filepath")
    echo -e "${BLUE}[*] Copying file '$filename' to container $sender...${NC}"
    docker cp "$filepath" "$sender:/tmp/$filename"

    echo -e "${BLUE}[*] Calling endpoint POST /api/p2p/send-file (to: ${recipient:-<default peer>})...${NC}"
    local to_args=()
    [ -n "$recipient" ] && to_args=(-F "to=$recipient")
    docker exec "$sender" curl -s -X POST http://localhost:8000/api/p2p/send-file \
        -F "file=@/tmp/$filename" "${to_args[@]}" | python3 -m json.tool
}

show_files() {
    local client
    client=$(require_client "${1:-2}")

    echo -e "\n${BLUE}=== RECEIVED FILES ON $client ===${NC}"
    docker exec "$client" curl -s http://localhost:8000/api/p2p/files | python3 -m json.tool
    echo ""
}

show_status() {
    echo -e "\n${BLUE}============================================================${NC}"
    echo -e "${BLUE}          EDGE NODES STATUS (${CLIENTS[*]})          ${NC}"
    echo -e "${BLUE}============================================================${NC}"
    ensure_networks
    for client in "${CLIENTS[@]}"; do
        local n app
        n=$(client_number "$client")
        app=$(app_container "$client")
        if is_container_running "$client"; then
            echo -e "  Edge client: ${CYAN}$client${NC}  ${GREEN}http://localhost:301$n (Swagger: /docs)${NC}"
            docker exec "$client" curl -s http://localhost:8000/api/status | python3 -m json.tool || true
        else
            echo -e "  Edge client: ${YELLOW}$client${NC} -> ${RED}STOPPED${NC}"
        fi
        if is_container_running "$app"; then
            echo -e "  Edge app:    ${CYAN}$app${NC}  ${GREEN}http://localhost:800$n (Swagger: /docs)${NC}"
        else
            echo -e "  Edge app:    ${YELLOW}$app${NC} -> ${RED}STOPPED${NC}"
        fi
        echo -e "------------------------------------------------------------"
    done
    show_links
}

# client_N -> app_N (the edge app paired with an edge client)
app_container() {
    echo "app_$(client_number "$1")"
}

# Root CA pinned at deployment: the fingerprint of the public CA certificate goes to .env (CA_FINGERPRINT),
# from which docker-compose.edge.yml passes it to every edge client and edge app. Without it a node accepts no CA.
CA_CERT_FILE="$SCRIPT_DIR/admin/backend/pki_data/ca_certificate.pem"
pin_ca() {
    local fp
    if [ -n "$CA_FINGERPRINT" ]; then
        fp="$CA_FINGERPRINT"
    elif [ -f "$CA_CERT_FILE" ]; then
        fp=$(openssl x509 -in "$CA_CERT_FILE" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')
    else
        echo -e "${YELLOW}[!] No $CA_CERT_FILE and no CA_FINGERPRINT – nodes will accept no Root CA. Start the centre first.${NC}"
        return 0
    fi
    touch "$SCRIPT_DIR/.env"
    sed -i '/^CA_FINGERPRINT=/d' "$SCRIPT_DIR/.env"
    echo "CA_FINGERPRINT=$fp" >> "$SCRIPT_DIR/.env"
    echo -e "${GREEN}[+] Root CA pinned: ${fp:0:16}...${NC}"
}

# csr <N>: edge client N generates a new key + request; the administrator approves it in the CA panel.
request_cert() {
    local client
    client=$(require_client "$1")
    echo -e "${BLUE}[*] $client: new key and certificate request (needs approval in the admin panel)...${NC}"
    docker exec "$client" curl -s -X POST http://localhost:8000/api/certs/csr | python3 -m json.tool
}

# crl-upload <N> <file>: CRL delivered out of band (stored only if signed by the Root CA and newer).
upload_crl() {
    local client
    client=$(require_client "$1")
    if [ ! -f "$2" ]; then
        echo -e "${RED}[ERROR] Usage: ./client.sh crl-upload 1 crl.der${NC}"
        exit 1
    fi
    docker cp "$2" "$client:/tmp/upload_crl"
    docker exec "$client" curl -s -X POST http://localhost:8000/api/certs/crl -F "crl=@/tmp/upload_crl" | python3 -m json.tool
    docker exec "$client" rm -f /tmp/upload_crl
}

# cert-download <N> [out.pem]: download the certificate (no key) from edge client N.
download_cert() {
    local client out
    client=$(require_client "$1")
    out="${2:-${client}_cert.pem}"
    if docker exec "$client" curl -sf "http://localhost:8000/api/certs/certificate" > "$out"; then
        echo -e "${GREEN}[+] Saved $client certificate to $out.${NC}"
    else
        rm -f "$out"
        echo -e "${RED}[ERROR] $client has no certificate yet.${NC}"
        exit 1
    fi
}

# cert-check <N> [file]: edge client N checks its certificate (or a certificate file) offline
# against its stored Root CA and CRL.
check_cert() {
    local client form=()
    client=$(require_client "$1")
    if [ -n "$2" ]; then
        if [ ! -f "$2" ]; then
            echo -e "${RED}[ERROR] Usage: ./client.sh cert-check 1 [cert.pem]${NC}"
            exit 1
        fi
        docker cp "$2" "$client:/tmp/check_cert"
        form=(-F "cert=@/tmp/check_cert")
    fi
    docker exec "$client" curl -s -X POST http://localhost:8000/api/certs/verify "${form[@]}" | python3 -m json.tool
    docker exec "$client" rm -f /tmp/check_cert
}

# fetch <N>: edge app N takes the certificate from its edge client (auth does this by itself).
fetch_cert() {
    local app
    app=$(app_container "$(require_client "$1")")
    echo -e "${BLUE}[*] $app takes the certificate from its edge client...${NC}"
    docker exec "$app" curl -s -X POST http://localhost:8000/api/pki/fetch | python3 -m json.tool
}

# auth <a> <b>: edge app a and edge app b authenticate each other with their certificates (app_net).
authenticate_apps() {
    local a b
    a=$(app_container "$(require_client "$1")")
    b=$(app_container "$(require_client "$2")")
    echo -e "${BLUE}[*] Mutual certificate authentication $a <-> $b...${NC}"
    docker exec "$a" curl -s -X POST http://localhost:8000/api/auth/peer \
        -H "Content-Type: application/json" -d "{\"peer\": \"$b\"}" | python3 -m json.tool
}

show_app_pki() {
    local targets
    targets=$(resolve_targets "${1:-all}") || exit 1
    for client in $targets; do
        local app
        app=$(app_container "$client")
        echo -e "\n${BLUE}=== PKI STORE OF $app ===${NC}"
        docker exec "$app" curl -s http://localhost:8000/api/pki/status | python3 -m json.tool || true
    done
}

# stats [N|all] [csv]: bytes sent/received by edge client(s), by kind of object and peer (transfers.py).
show_stats() {
    local targets
    targets=$(resolve_targets "${1:-all}") || exit 1
    for client in $targets; do
        if [ "$2" = "csv" ]; then
            docker exec "$client" curl -s "http://localhost:8000/api/stats/transfers?format=csv"
            continue
        fi
        echo -e "\n${BLUE}=== TRANSFERS OF $client ===${NC}"
        docker exec "$client" curl -s http://localhost:8000/api/stats/transfers | python3 -c '
import json, sys
s = json.load(sys.stdin)
row = "{:<12} {:>6} {:>10} {:>10} {:>10}  {}"
print(row.format("", "count", "payload", "wire", "saved", "statuses"))
def show(name, v):
    st = " ".join(f"{k[7:]}={n}" for k, n in sorted(v.items()) if k.startswith("status_"))
    print(row.format(name, v["count"], v["payload_bytes"], v["wire_bytes"], v["saved_bytes"], st))
for group in ("by_kind", "by_peer", "by_direction"):
    print(f"-- {group[3:]}")
    for name, v in s[group].items():
        show(name, v)
show("TOTAL", s["total"])
' || true
    done
}

call_custom_endpoint() {
    local client
    client=$(require_client "$1")
    local endpoint="$2"

    if [ -z "$endpoint" ]; then
        echo -e "${RED}[ERROR] Provide endpoint. Usage: ./client.sh call 1 /api/status${NC}"
        exit 1
    fi

    echo -e "${BLUE}[*] Calling $endpoint on $client:${NC}"
    docker exec "$client" curl -s "http://localhost:8000$endpoint" | python3 -m json.tool || true
}

show_help() {
    cat << EOF
Łączność – edge nodes: Edge client client_1..3 (UI :3011-3013) + Edge app app_1..3 (UI :8001-8003)
============================================================
Initial radio links: client_1 --p2p_12-- client_2 --p2p_23-- client_3
Neighbours are greeted once when a link comes up; messages and files go only to nodes in radio range.
Each edge client holds one certificate: it generates the key itself, sends a CSR on WAN contact and installs
the certificate once the administrator approves it in the CA panel. Its edge app uses it only to authenticate.

Lifecycle and status:
  ./client.sh up [--offline|--online]  Start containers (background)
  ./client.sh down                     Stop containers (node data volumes are kept)
  ./client.sh restart                  Restart containers
  ./client.sh status                   Display status JSON from /api/status + radio links
  ./client.sh links                    Display radio links (P2P networks and members)

Internet Flag (Enable / Disable):
  ./client.sh internet on [1|2|3|all]  Enable Internet access
  ./client.sh internet off [1|2|3|all] Disable Internet access

Radio link (P2P) simulation (any pair of nodes):
  ./client.sh link down 1 2            Break radio link client_1 <-> client_2
  ./client.sh link up 1 3              Bring client_1 and client_3 into radio range (creates p2p_13)

Endpoint execution:
  ./client.sh clock [1|2|3|all]          GET /api/clock (external clock)
  ./client.sh p2p-test [1|2|3|all]       GET /api/p2p/test (P2P connectivity to neighbours)
  ./client.sh internet-test [1|2|3|all]  GET /api/internet/test (WAN RTT test)
  ./client.sh internet-check [1|2|3|all] GET /api/internet/check (socket diagnostics)

P2P Communication (directly in radio range, otherwise store-and-forward via neighbours):
  ./client.sh msg 1 3 "Text"           Send P2P message from client_1 to client_3
  ./client.sh inbox [1|2|3]            Display P2P inbox
  ./client.sh send-file 1 3 <file>     Send file via P2P from client_1 to client_3
  ./client.sh files [1|2|3]            List received P2P files
  ./client.sh queue [1|2|3|all]        Store-and-forward queue (items carried for nodes out of range)
  ./client.sh contacts [1|2|3]         Latest contacts (WAN / neighbour) and results of their exchanges

Measurements (bytes on WAN / radio links):
  ./client.sh stats [1|2|3|all] [csv]  Transfers by kind, peer and direction (csv: every record)
  ./client.sh stats-reset [1|2|3|all]  Clear the transfer register before a scenario
  ./client.sh call 1 <path>            Call custom endpoint
  ./client.sh logs [1|2|3]             Follow edge client uvicorn logs

Certificates (held by the edge client, obtained automatically, used by the edge app):
  ./client.sh csr 1                    New key + certificate request (e.g. after a rejection)
  ./client.sh crl-upload 1 crl.der     CRL delivered out of band (stored only if signed and newer)
  ./client.sh certs [1|2|3]            Certificate, Root CA and CRL held by the edge client
  ./client.sh cert-download 1 [f]      Download the certificate (PEM, no key)
  ./client.sh cert-check 1 [file]      Check the certificate (or a file) offline in edge client 1
  ./client.sh fetch 1                  app_1 takes the certificate from edge client 1 (auth does it itself)
  ./client.sh pki [1|2|3|all]          PKI store of the edge app(s)
  ./client.sh auth 1 2                 app_1 and app_2 authenticate each other (challenge-response, app_net)
  ./client.sh app-logs [1|2|3]         Follow edge app uvicorn logs
EOF
}

case "$1" in
    up)
        ensure_networks
        pin_ca
        echo -e "${BLUE}[*] Building and starting containers (${CLIENTS[*]})...${NC}"
        docker compose -f "$COMPOSE_FILE" up -d --build
        if [ "$2" = "--online" ]; then
            set_internet on all
        else
            echo -e "${YELLOW}[*] Containers started in default mode: OFFLINE (No Internet).${NC}"
        fi
        show_status
        ;;
    down)
        echo -e "${YELLOW}[*] Stopping containers...${NC}"
        docker compose -f "$COMPOSE_FILE" down
        for net in $(docker network ls -q --filter "label=$P2P_LABEL"); do
            docker network rm "$net" >/dev/null && echo -e "${YELLOW}[-] Removed radio link network $net.${NC}"
        done
        echo -e "${GREEN}[+] Stopped.${NC}"
        ;;
    restart)
        docker compose -f "$COMPOSE_FILE" restart
        show_status
        ;;
    internet)
        if [ "$2" != "on" ] && [ "$2" != "off" ]; then
            echo -e "${RED}[ERROR] Usage: ./client.sh internet on [1|2|3|all] OR ./client.sh internet off [1|2|3|all]${NC}"
            exit 1
        fi
        set_internet "$2" "${3:-all}"
        ;;
    link)
        if { [ "$2" != "up" ] && [ "$2" != "down" ]; } || [ -z "$3" ] || [ -z "$4" ]; then
            echo -e "${RED}[ERROR] Usage: ./client.sh link up|down <a> <b>   (e.g. ./client.sh link down 1 2)${NC}"
            exit 1
        fi
        set_link "$2" "$3" "$4"
        ;;
    links)
        show_links
        ;;
    clock)
        run_endpoint /api/clock "${2:-all}"
        ;;
    p2p-test|p2p-ping|radio-ping|ping)
        run_endpoint /api/p2p/test "${2:-all}"
        ;;
    internet-check)
        run_endpoint /api/internet/check "${2:-all}"
        ;;
    internet-test|internet-ping)
        run_endpoint /api/internet/test "${2:-all}"
        ;;
    msg)
        shift
        send_p2p_message "$@"
        ;;
    inbox)
        show_inbox "${2:-2}"
        ;;
    send-file)
        shift
        send_file_p2p "$@"
        ;;
    files)
        show_files "${2:-2}"
        ;;
    call)
        call_custom_endpoint "$2" "$3"
        ;;
    queue)
        run_endpoint /api/saf/queue "${2:-all}"
        ;;
    contacts)
        docker exec "$(require_client "${2:-1}")" curl -s "http://localhost:8000/api/contact/events?limit=10" | python3 -m json.tool
        ;;
    stats)
        show_stats "${2:-all}" "$3"
        ;;
    stats-reset)
        for client in $(resolve_targets "${2:-all}"); do
            docker exec "$client" curl -s -X DELETE http://localhost:8000/api/stats/transfers; echo
        done
        ;;
    status)
        show_status
        ;;
    logs)
        docker logs -f "$(require_client "${2:-1}")"
        ;;
    csr)
        request_cert "${2:-1}"
        ;;
    crl-upload)
        upload_crl "$2" "$3"
        ;;
    certs)
        docker exec "$(require_client "${2:-1}")" curl -s http://localhost:8000/api/certs | python3 -m json.tool
        ;;
    cert-download)
        download_cert "$2" "$3"
        ;;
    cert-check)
        check_cert "$2" "$3"
        ;;
    fetch)
        fetch_cert "$2"
        ;;
    pki)
        show_app_pki "${2:-all}"
        ;;
    auth)
        if [ -z "$2" ] || [ -z "$3" ]; then
            echo -e "${RED}[ERROR] Usage: ./client.sh auth <a> <b>   (e.g. ./client.sh auth 1 2)${NC}"
            exit 1
        fi
        authenticate_apps "$2" "$3"
        ;;
    app-logs)
        docker logs -f "$(app_container "$(require_client "${2:-1}")")"
        ;;
    *)
        show_help
        ;;
esac
