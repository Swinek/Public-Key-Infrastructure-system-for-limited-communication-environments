#!/usr/bin/env bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
CLIENTS=("client_1" "client_2" "client_3")
INTERNET_NET="internet_net"
# Radio links: one Docker network per link, p2p_<a><b> (a < b) connects client_a and client_b.
# p2p_12 and p2p_23 come from docker-compose.yml; any other pair is created on demand by `link up`
# (labelled P2P_LABEL, removed by `down`).
P2P_LABEL="pki.edges.p2p-link=dynamic"

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
        echo -e "${GREEN}[+] Radio link $a <-> $b is UP.${NC}"
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
    echo -e "${BLUE}          CLIENT NODES STATUS (${CLIENTS[*]})          ${NC}"
    echo -e "${BLUE}============================================================${NC}"
    ensure_networks
    for client in "${CLIENTS[@]}"; do
        if is_container_running "$client"; then
            local port="800$(client_number "$client")"
            echo -e "  Node: ${CYAN}$client${NC}"
            echo -e "  Host: ${GREEN}http://localhost:$port (Swagger: http://localhost:$port/docs)${NC}"
            docker exec "$client" curl -s http://localhost:8000/api/status | python3 -m json.tool || true
        else
            echo -e "  Node: ${YELLOW}$client${NC} -> ${RED}STOPPED${NC}"
        fi
        echo -e "------------------------------------------------------------"
    done
    show_links
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
Edge Nodes Management (Edge App #1, #2, #3):
============================================================
Initial radio links: client_1 --p2p_12-- client_2 --p2p_23-- client_3
Nodes discover neighbours by beacons; messages and files go only to nodes in radio range.

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

P2P Communication:
  ./client.sh msg 1 2 "Text"           Send P2P message from client_1 to client_2 (must be in radio range)
  ./client.sh inbox [1|2|3]            Display P2P inbox
  ./client.sh send-file 1 2 <file>     Send file via P2P from client_1 to client_2 (in radio range)
  ./client.sh files [1|2|3]            List received P2P files
  ./client.sh call 1 <path>            Call custom endpoint
  ./client.sh logs [1|2|3]             Follow uvicorn logs
EOF
}

case "$1" in
    up)
        ensure_networks
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
    status)
        show_status
        ;;
    logs)
        docker logs -f "$(require_client "${2:-1}")"
        ;;
    *)
        show_help
        ;;
esac
