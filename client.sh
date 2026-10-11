#!/usr/bin/env bash

set -e

COMPOSE_FILE="docker-compose.clients.yml"
CLIENTS=("client_1" "client_2")
INTERNET_NET="internet_net"
P2P_NET="isolated_p2p_net"

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

has_internet_access() {
    local name="$1"
    docker inspect "$name" --format '{{json .NetworkSettings.Networks}}' 2>/dev/null | grep -q "\"$INTERNET_NET\""
}

get_client_container() {
    local target="$1"
    if [ "$target" = "1" ] || [ "$target" = "client_1" ] || [ "$target" = "client1" ]; then
        echo "client_1"
    elif [ "$target" = "2" ] || [ "$target" = "client_2" ] || [ "$target" = "client2" ]; then
        echo "client_2"
    else
        echo "$target"
    fi
}

set_internet() {
    local action="$1"
    local target="$2"

    ensure_networks

    local targets=()
    if [ "$target" = "all" ] || [ -z "$target" ]; then
        targets=("${CLIENTS[@]}")
    elif [ "$target" = "1" ] || [ "$target" = "client_1" ] || [ "$target" = "client1" ]; then
        targets=("client_1")
    elif [ "$target" = "2" ] || [ "$target" = "client_2" ] || [ "$target" = "client2" ]; then
        targets=("client_2")
    else
        echo -e "${RED}[ERROR] Unknown client: '$target'. Available: 1, 2, client_1, client_2, all${NC}"
        exit 1
    fi

    for client in "${targets[@]}"; do
        if ! is_container_running "$client"; then
            echo -e "${YELLOW}[!] Container $client is not running. Start first: ./client.sh up${NC}"
            continue
        fi

        if [ "$action" = "on" ]; then
            if has_internet_access "$client"; then
                echo -e "${CYAN}[i] $client: Internet is ALREADY enabled (ONLINE).${NC}"
            else
                docker network connect "$INTERNET_NET" "$client"
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

run_clock_endpoint() {
    local target="$1"
    local targets=()
    if [ "$target" = "all" ] || [ -z "$target" ]; then
        targets=("${CLIENTS[@]}")
    elif [ "$target" = "1" ] || [ "$target" = "client_1" ]; then
        targets=("client_1")
    elif [ "$target" = "2" ] || [ "$target" = "client_2" ]; then
        targets=("client_2")
    else
        targets=("$target")
    fi

    for client in "${targets[@]}"; do
        if ! is_container_running "$client"; then
            echo -e "${RED}[!] Container $client is not running.${NC}"
            continue
        fi
        echo -e "\n${BLUE}============================================================${NC}"
        echo -e "  ENDPOINT: ${MAGENTA}GET /api/clock${NC} on ${CYAN}$client${NC}"
        echo -e "${BLUE}------------------------------------------------------------${NC}"
        docker exec "$client" curl -s http://localhost:8000/api/clock | python3 -m json.tool || true
    done
    echo ""
}

run_internet_check_endpoint() {
    local target="$1"
    local targets=()
    if [ "$target" = "all" ] || [ -z "$target" ]; then
        targets=("${CLIENTS[@]}")
    elif [ "$target" = "1" ] || [ "$target" = "client_1" ]; then
        targets=("client_1")
    elif [ "$target" = "2" ] || [ "$target" = "client_2" ]; then
        targets=("client_2")
    else
        targets=("$target")
    fi

    for client in "${targets[@]}"; do
        if ! is_container_running "$client"; then
            echo -e "${RED}[!] Container $client is not running.${NC}"
            continue
        fi
        echo -e "\n${BLUE}============================================================${NC}"
        echo -e "  ENDPOINT: ${MAGENTA}GET /api/internet/check${NC} on ${CYAN}$client${NC}"
        echo -e "${BLUE}------------------------------------------------------------${NC}"
        docker exec "$client" curl -s http://localhost:8000/api/internet/check | python3 -m json.tool || true
    done
    echo ""
}

run_p2p_test_endpoint() {
    for client in "${CLIENTS[@]}"; do
        if ! is_container_running "$client"; then
            echo -e "${RED}[!] Container $client is not running.${NC}"
            continue
        fi
        echo -e "\n${BLUE}============================================================${NC}"
        echo -e "  ENDPOINT: ${MAGENTA}GET /api/p2p/test${NC} on ${CYAN}$client${NC}"
        echo -e "${BLUE}------------------------------------------------------------${NC}"
        docker exec "$client" curl -s http://localhost:8000/api/p2p/test | python3 -m json.tool || true
    done
    echo ""
}

run_internet_test_endpoint() {
    local target="$1"
    local targets=()
    if [ "$target" = "all" ] || [ -z "$target" ]; then
        targets=("${CLIENTS[@]}")
    elif [ "$target" = "1" ] || [ "$target" = "client_1" ]; then
        targets=("client_1")
    elif [ "$target" = "2" ] || [ "$target" = "client_2" ]; then
        targets=("client_2")
    else
        targets=("$target")
    fi

    for client in "${targets[@]}"; do
        if ! is_container_running "$client"; then
            echo -e "${RED}[!] Container $client is not running.${NC}"
            continue
        fi
        echo -e "\n${BLUE}============================================================${NC}"
        echo -e "  ENDPOINT: ${MAGENTA}GET /api/internet/test${NC} on ${CYAN}$client${NC}"
        echo -e "${BLUE}------------------------------------------------------------${NC}"
        docker exec "$client" curl -s http://localhost:8000/api/internet/test | python3 -m json.tool || true
    done
    echo ""
}

send_p2p_message() {
    local sender_raw="$1"
    local msg="$2"
    local sender=$(get_client_container "$sender_raw")

    if [ -z "$msg" ]; then
        echo -e "${RED}[ERROR] Provide message content. Usage: ./client.sh msg 1 \"Message text\"${NC}"
        exit 1
    fi

    echo -e "${BLUE}[*] Sending message from $sender...${NC}"
    docker exec "$sender" curl -s -X POST http://localhost:8000/api/p2p/send-message \
        -H "Content-Type: application/json" \
        -d "{\"message\": \"$msg\"}" | python3 -m json.tool
}

show_inbox() {
    local target_raw="$1"
    local client=$(get_client_container "${target_raw:-2}")

    echo -e "\n${BLUE}=== P2P INBOX FOR $client ===${NC}"
    docker exec "$client" curl -s http://localhost:8000/api/p2p/inbox | python3 -m json.tool
    echo ""
}

send_file_p2p() {
    local sender_raw="$1"
    local filepath="$2"
    local sender=$(get_client_container "$sender_raw")

    if [ ! -f "$filepath" ]; then
        echo -e "${RED}[ERROR] File '$filepath' does not exist on disk.${NC}"
        exit 1
    fi

    local filename=$(basename "$filepath")
    echo -e "${BLUE}[*] Copying file '$filename' to container $sender...${NC}"
    docker cp "$filepath" "$sender:/tmp/$filename"

    echo -e "${BLUE}[*] Calling endpoint POST /api/p2p/send-file...${NC}"
    docker exec "$sender" curl -s -X POST http://localhost:8000/api/p2p/send-file \
        -F "file=@/tmp/$filename" | python3 -m json.tool
}

show_files() {
    local target_raw="$1"
    local client=$(get_client_container "${target_raw:-2}")

    echo -e "\n${BLUE}=== RECEIVED FILES ON $client ===${NC}"
    docker exec "$client" curl -s http://localhost:8000/api/p2p/files | python3 -m json.tool
    echo ""
}

show_status() {
    echo -e "\n${BLUE}============================================================${NC}"
    echo -e "${BLUE}             CLIENT NODES STATUS (CLIENT 1 & 2)             ${NC}"
    echo -e "${BLUE}============================================================${NC}"
    ensure_networks
    for client in "${CLIENTS[@]}"; do
        if is_container_running "$client"; then
            local port_url=""
            [ "$client" = "client_1" ] && port_url="http://localhost:8001 (Swagger: http://localhost:8001/docs)"
            [ "$client" = "client_2" ] && port_url="http://localhost:8002 (Swagger: http://localhost:8002/docs)"

            echo -e "  Node: ${CYAN}$client${NC}"
            echo -e "  Host: ${GREEN}$port_url${NC}"
            docker exec "$client" curl -s http://localhost:8000/api/status | python3 -m json.tool || true
        else
            echo -e "  Node: ${YELLOW}$client${NC} -> ${RED}STOPPED${NC}"
        fi
        echo -e "------------------------------------------------------------"
    done
    echo ""
}

call_custom_endpoint() {
    local client_raw="$1"
    local endpoint="$2"
    local client=$(get_client_container "$client_raw")

    if [ -z "$endpoint" ]; then
        echo -e "${RED}[ERROR] Provide endpoint. Usage: ./client.sh call 1 /api/status${NC}"
        exit 1
    fi

    echo -e "${BLUE}[*] Calling $endpoint on $client:${NC}"
    docker exec "$client" curl -s "http://localhost:8000$endpoint" | python3 -m json.tool || true
}

show_help() {
    cat << EOF
Client Nodes Management (Client 1 & Client 2):
============================================================
Lifecycle and status:
  ./client.sh up [--offline|--online]  Start containers (background)
  ./client.sh down                     Stop containers
  ./client.sh restart                  Restart containers
  ./client.sh status                   Display status JSON from /api/status

Internet Flag (Enable / Disable):
  ./client.sh internet on [1|2|all]    Enable Internet access
  ./client.sh internet off [1|2|all]   Disable Internet access

Endpoint execution:
  ./client.sh clock [1|2|all]          GET /api/clock (external clock)
  ./client.sh p2p-test                 GET /api/p2p/test (P2P connectivity)
  ./client.sh internet-test [1|2|all]  GET /api/internet/test (WAN RTT test)
  ./client.sh internet-check [1|2|all] GET /api/internet/check (socket diagnostics)

P2P Communication:
  ./client.sh msg 1 "Text"             Send P2P message from Client 1 to Client 2
  ./client.sh inbox [1|2]              Display P2P inbox
  ./client.sh send-file 1 <file>       Send file via P2P with SHA-256 verification
  ./client.sh files [1|2]              List received P2P files
  ./client.sh call 1 <path>            Call custom endpoint
  ./client.sh logs [1|2]               Follow uvicorn logs
EOF
}

case "$1" in
    up)
        ensure_networks
        echo -e "${BLUE}[*] Building and starting containers (Client 1 & Client 2)...${NC}"
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
        echo -e "${GREEN}[+] Stopped.${NC}"
        ;;
    restart)
        docker compose -f "$COMPOSE_FILE" restart
        show_status
        ;;
    internet)
        if [ "$2" != "on" ] && [ "$2" != "off" ]; then
            echo -e "${RED}[ERROR] Usage: ./client.sh internet on [1|2|all] OR ./client.sh internet off [1|2|all]${NC}"
            exit 1
        fi
        set_internet "$2" "${3:-all}"
        ;;
    clock)
        run_clock_endpoint "${2:-all}"
        ;;
    p2p-test|p2p-ping|radio-ping|ping)
        run_p2p_test_endpoint
        ;;
    internet-check)
        run_internet_check_endpoint "${2:-all}"
        ;;
    internet-test|internet-ping)
        run_internet_test_endpoint "${2:-all}"
        ;;
    msg)
        send_p2p_message "$2" "$3"
        ;;
    inbox)
        show_inbox "${2:-2}"
        ;;
    send-file)
        send_file_p2p "$2" "$3"
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
        docker logs -f "$(get_client_container "${2:-client_1}")"
        ;;
    *)
        show_help
        ;;
esac
