#!/bin/bash

set -e

#======================
# REMNAWAVE DB MIGRATE
#======================

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly GRAY='\033[0;90m'
readonly NC='\033[0m'

readonly CHECK="✓"
readonly CROSS="✗"
readonly WARNING="!"
readonly INFO="*"
readonly ARROW="→"

readonly PANEL_DIR="/opt/remnawave"
readonly DB_CONTAINER="remnawave-db"
readonly EXCLUDE_PATTERNS="*.log *.tmp .git"

#==================
# HELPER FUNCTIONS
#==================

error() {
    echo
    echo -e "${RED}${CROSS}${NC} $1"
    echo
    exit 1
}

show_header() {
    echo
    echo -e "${PURPLE}=====================${NC}"
    echo -e "${WHITE}REMNAWAVE DB MIGRATE${NC}"
    echo -e "${PURPLE}=====================${NC}"
    echo
}

show_menu() {
    echo -e "${CYAN}Please select action:${NC}"
    echo
    echo -e "${GREEN}1.${NC} Backup"
    echo -e "${GREEN}2.${NC} Restore"
    echo -e "${RED}3.${NC} Exit"
    echo
    echo -ne "${CYAN}Enter your choice (1, 2, or 3): ${NC}"
}

#=================
# BACKUP FUNCTION
#=================

get_db_user() {
    docker exec "$DB_CONTAINER" bash -c 'echo $POSTGRES_USER' 2>/dev/null | tr -d '[:space:]'
}

get_db_name() {
    docker exec "$DB_CONTAINER" bash -c 'echo $POSTGRES_DB' 2>/dev/null | tr -d '[:space:]'
}

do_backup() {
    local timestamp
    timestamp=$(date +%Y-%m-%d_%H-%M-%S)
    local archive_name="remnawave_backup_${timestamp}.tar.gz"
    local work_dir
    work_dir=$(mktemp -d)

    trap 'rm -rf "$work_dir"' EXIT

    echo -e "${CYAN}${INFO}${NC} Checking database container..."
    echo -e "${GRAY}  ${ARROW}${NC} Container: ${DB_CONTAINER}"
    if ! docker inspect "$DB_CONTAINER" > /dev/null 2>&1 || \
       ! docker container inspect -f '{{.State.Running}}' "$DB_CONTAINER" 2>/dev/null | grep -q "true"; then
        error "Container ${DB_CONTAINER} is not running."
    fi
    echo -e "${GREEN}${CHECK}${NC} Container is running."
    echo
    echo -e "${CYAN}${INFO}${NC} Dumping database..."
    local db_user
    db_user=$(get_db_user)
    echo -e "${GRAY}  ${ARROW}${NC} User: ${db_user}"
    local db_dump="$work_dir/dump_${timestamp}.sql.gz"
    local error_log
    error_log=$(mktemp)

    docker exec "$DB_CONTAINER" pg_dumpall -c -U "$db_user" 2>"$error_log" | gzip -9 > "$db_dump"
    if [[ ${PIPESTATUS[0]} -ne 0 ]]; then
        cat "$error_log" >&2
        rm -f "$error_log"
        error "Database dump failed."
    fi
    rm -f "$error_log"
    echo -e "${GREEN}${CHECK}${NC} Database dumped."
    echo
    echo -e "${CYAN}${INFO}${NC} Archiving panel directory..."
    echo -e "${GRAY}  ${ARROW}${NC} Source: ${PANEL_DIR}"
    local dir_archive="$work_dir/remnawave_dir_${timestamp}.tar.gz"
    local exclude_args=()
    for pat in $EXCLUDE_PATTERNS; do
        exclude_args+=(--exclude="$pat")
    done
    tar -czf "$dir_archive" "${exclude_args[@]}" -C "$(dirname "$PANEL_DIR")" "$(basename "$PANEL_DIR")"
    echo -e "${GREEN}${CHECK}${NC} Directory archived."
    echo
    echo -e "${CYAN}${INFO}${NC} Creating final archive..."
    echo -e "${GRAY}  ${ARROW}${NC} File: ./${archive_name}"
    tar -czf "./$archive_name" -C "$work_dir" .
    trap - EXIT
    rm -rf "$work_dir"

    local size
    size=$(du -sh "./$archive_name" 2>/dev/null | cut -f1)
    echo -e "${GREEN}${CHECK}${NC} Backup created."

    echo
    echo -e "${PURPLE}==================${NC}"
    echo -e "${GREEN}${CHECK}${NC} Backup complete"
    echo -e "${PURPLE}==================${NC}"
    echo
    echo -e "${CYAN}File:${NC}"
    echo -e "${WHITE}./${archive_name} (${size})${NC}"
    echo
}

#==================
# RESTORE FUNCTION
#==================

do_restore() {
    local backup_file="${1:-}"

    if [[ -z "$backup_file" ]]; then
        backup_file=$(find . -maxdepth 1 -name "remnawave_backup_*.tar.gz" | sort -r | head -n 1)
        if [[ -z "$backup_file" ]]; then
            error "No backup files found in current directory."
        fi
    fi

    [[ -f "$backup_file" ]] || error "File not found: ${backup_file}"

    local size
    size=$(du -sh "$backup_file" 2>/dev/null | cut -f1)

    echo -e "${YELLOW}${WARNING}${NC} This will DESTROY the current installation!"
    echo -e "${GRAY}  ${ARROW}${NC} File: ${backup_file} (${size})"
    echo
    echo -ne "${YELLOW}Are you sure you want to continue? (y/n): ${NC}"
    read -r confirm

    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo -e "${RED}${CROSS}${NC} Restore aborted by user"
        exit 1
    fi

    echo

    local work_dir
    work_dir=$(mktemp -d)
    trap 'rm -rf "$work_dir"' EXIT

    echo -e "${CYAN}${INFO}${NC} Extracting backup archive..."
    echo -e "${GRAY}  ${ARROW}${NC} Source: ${backup_file}"
    tar -xzf "$backup_file" -C "$work_dir"

    local db_dump
    db_dump=$(find "$work_dir" -name "dump_*.sql.gz" | head -n 1)
    local dir_archive
    dir_archive=$(find "$work_dir" -name "remnawave_dir_*.tar.gz" | head -n 1)

    [[ -n "$db_dump" ]]    || error "Database dump not found in backup."
    [[ -n "$dir_archive" ]] || error "Directory archive not found in backup."
    echo -e "${GREEN}${CHECK}${NC} Archive extracted."
    echo
    echo -e "${CYAN}${INFO}${NC} Stopping containers..."
    if [[ -d "$PANEL_DIR" ]]; then
        echo -e "${GRAY}  ${ARROW}${NC} Running docker compose down"
        cd "$PANEL_DIR" && docker compose down 2>/dev/null || true
        cd /
    fi
    echo -e "${GREEN}${CHECK}${NC} Containers stopped."
    echo
    echo -e "${CYAN}${INFO}${NC} Replacing panel directory..."
    echo -e "${GRAY}  ${ARROW}${NC} Target: ${PANEL_DIR}"
    rm -rf "$PANEL_DIR"
    mkdir -p "$(dirname "$PANEL_DIR")"

    local extract_dir="$work_dir/dir_extract"
    mkdir -p "$extract_dir"
    tar -xzf "$dir_archive" -C "$extract_dir"

    local extracted_subdir
    extracted_subdir=$(find "$extract_dir" -mindepth 1 -maxdepth 1 -type d | head -n 1)
    cp -rf "$extracted_subdir"/. "$PANEL_DIR/"
    echo -e "${GREEN}${CHECK}${NC} Directory restored."
    echo
    echo -e "${CYAN}${INFO}${NC} Removing old database volume..."
    echo -e "${GRAY}  ${ARROW}${NC} Volume: remnawave-db-data"
    docker volume rm remnawave-db-data > /dev/null 2>&1 || true
    echo -e "${GREEN}${CHECK}${NC} Volume removed."
    echo
    echo -e "${CYAN}${INFO}${NC} Starting database container..."
    echo -e "${GRAY}  ${ARROW}${NC} Container: ${DB_CONTAINER}"
    cd "$PANEL_DIR"
    docker compose up -d "$DB_CONTAINER" > /dev/null 2>&1
    echo -e "${GREEN}${CHECK}${NC} Database container started."
    echo
    echo -e "${CYAN}${INFO}${NC} Waiting for database to become healthy..."
    echo -e "${GRAY}  ${ARROW}${NC} Container: ${DB_CONTAINER}"
    local attempts=0
    until [[ "$(docker inspect --format='{{.State.Health.Status}}' "$DB_CONTAINER" 2>/dev/null)" == "healthy" ]]; do
        sleep 2
        attempts=$((attempts + 1))
        if (( attempts > 60 )); then
            error "Database did not become healthy after 2 minutes."
        fi
    done
    echo -e "${GREEN}${CHECK}${NC} Database is healthy."
    echo
    echo -e "${CYAN}${INFO}${NC} Restoring database dump..."
    local db_user db_name
    db_user=$(get_db_user)
    db_name=$(get_db_name)
    echo -e "${GRAY}  ${ARROW}${NC} User: ${db_user}, DB: ${db_name}"
    local restore_log
    restore_log=$(mktemp)
    local sql_file="${db_dump%.gz}"
    gunzip "$db_dump"
    if ! docker exec -i "$DB_CONTAINER" psql -q -U "$db_user" -d "$db_name" > /dev/null 2>"$restore_log" < "$sql_file"; then
        echo -e "${RED}${CROSS}${NC} Restore errors:"
        cat "$restore_log"
        rm -f "$restore_log"
        error "Database restore failed."
    fi
    rm -f "$restore_log"
    echo -e "${GREEN}${CHECK}${NC} Database restored."
    echo
    echo -e "${CYAN}${INFO}${NC} Starting all containers..."
    echo -e "${GRAY}  ${ARROW}${NC} Directory: ${PANEL_DIR}"
    docker compose up -d > /dev/null 2>&1
    echo -e "${GREEN}${CHECK}${NC} All containers started."

    trap - EXIT
    rm -rf "$work_dir"

    echo
    echo -e "${PURPLE}===================${NC}"
    echo -e "${GREEN}${CHECK}${NC} Restore complete"
    echo -e "${PURPLE}===================${NC}"
    echo
    echo -e "${CYAN}Panel directory:${NC}"
    echo -e "${WHITE}${PANEL_DIR}${NC}"
    echo
}

#======
# MAIN
#======

show_header

case "${1:-}" in
    backup)
        do_backup
        ;;
    restore)
        do_restore "${2:-}"
        ;;
    "")
        show_menu
        read -r choice
        echo
        case "$choice" in
            1) do_backup ;;
            2) do_restore ;;
            3) exit 0 ;;
            *) echo -e "${RED}${CROSS}${NC} Invalid choice"; exit 1 ;;
        esac
        ;;
    *)
        echo -e "${RED}${CROSS}${NC} Unknown command: $1"
        echo -e "${CYAN}Usage:${NC} $0 {backup|restore [file]}"
        exit 1
        ;;
esac
