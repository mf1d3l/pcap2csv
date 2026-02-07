#!/usr/bin/env sh
#
# =============================================================================
# pcap2csv - Fast PCAP triage into analyst-friendly CSV output
# =============================================================================
#
# Purpose:
#   Process a PCAP file with Suricata and produce CSV outputs for forensic analysis.
#   Extracts discrete events and generates a chronological timeline, making it
#   easy to visualize or import into tools like EZ Timeline Explorer.
#
# Key Features:
#   - Runs Suricata on a PCAP file with optional custom rules (-R <rules_file>).
#   - Exports multiple event types to separate CSVs:
#       • Alerts          (signature, category, severity, etc.)
#       • DNS             (queries, responses, answers)
#       • HTTP            (request/response metadata)
#       • TLS             (SNI, certificate info, JA3 fingerprint)
#       • FTP             (commands and file transfers)
#       • Flows           (connection stats, packet/byte counts)
#   - Generates a unified timeline CSV for discrete events (alert, dns, http, tls, ftp):
#       • event_norm_data provides a human-readable summary per event
#       • extra contains the remaining JSON for detailed inspection
#   - Fully portable: works on POSIX shells, WSL, Linux, macOS.
#
# Output Strategy:
#   - All CSVs are written to a single output folder (pcap2csv_output by default)
#   - Filenames include the PCAP basename to avoid overwriting multiple runs
#   - Timeline excludes flows to maintain meaningful chronological ordering
#
# Dependencies:
#   - suricata (>=7.x recommended)
#   - jq
#
# Usage:
#   ./pcap2csv.sh <pcap_file> [-R <suricata_rules_file>]
# =============================================================================

set -e

############################
# GLOBAL VARIABLES
############################

PCAP=""
OUTDIR="pcap2csv_output"
EVE_JSON=""
PCAP_BASENAME=""
ALERTS_CSV=""
DNS_CSV=""
HTTP_CSV=""
TLS_CSV=""
FLOWS_CSV=""
TIMELINE_CSV=""
CUSTOM_RULES_FILE=""


print_banner() {
cat << 'EOF'
                           ___
    ____  _________ _____ |__ \ ___________   __
   / __ \/ ___/ __ `/ __ \__/ // ___/ ___/ | / /
  / /_/ / /__/ /_/ / /_/ / __// /__(__  )| |/ /
 / .___/\___/\__,_/ .___/____/\___/____/ |___/
/_/              /_/

**Fast PCAP triage into analyst-friendly CSV output**

EOF
}


############################
# LOGGING
############################

log() {
    if date -Iseconds >/dev/null 2>&1; then
        ts=$(date -Iseconds)
    else
        ts=$(date '+%Y-%m-%dT%H:%M:%S')
    fi
    echo "[$ts] [+] $*"
}

error() {
    if date -Iseconds >/dev/null 2>&1; then
        ts=$(date -Iseconds)
    else
        ts=$(date '+%Y-%m-%dT%H:%M:%S')
    fi
    echo "[$ts] [-] $*" >&2
    exit 1
}

############################
# USAGE
############################

usage() {
    echo "Usage: $0 <pcap_file> [-R <rules_file>]"
    echo ""
    echo "Options:"
    echo "  -R, --rules   Path to a Suricata rules file"
    exit 1
}

############################
# ARGUMENT PARSING
############################

parse_args() {
    PCAP=""
    CUSTOM_RULES_FILE=""

    # No args at all → usage
    [ $# -eq 0 ] && usage

    while [ $# -gt 0 ]; do
        case "$1" in
            -h|--help)
                usage
                ;;

            -R|--rules)
                if [ -z "$2" ] || [[ "$2" == -* ]]; then
                    error "-R|--rules requires a file path"
                fi
                CUSTOM_RULES_FILE="$2"
                shift 2
                ;;

            -*)
                error "Unknown option: $1"
                ;;

            *)
                # First non-flag argument is the PCAP
                if [ -z "$PCAP" ]; then
                    PCAP="$1"
                else
                    error "Unexpected extra argument: $1"
                fi
                shift
                ;;
        esac
    done

    # Final validation
    if [ -z "$PCAP" ]; then
        error "No PCAP file provided"
    fi

    if [ ! -f "$PCAP" ]; then
        error "PCAP file not found: $PCAP"
    fi

    if [ -n "$CUSTOM_RULES_FILE" ] && [ ! -f "$CUSTOM_RULES_FILE" ]; then
        error "Custom rules file not found: $CUSTOM_RULES_FILE"
    fi
}




############################
# DEPENDENCY CHECK
############################

check_dependencies() {
    log "Checking dependencies"

    command -v suricata >/dev/null 2>&1 || error "suricata not found"
    command -v jq >/dev/null 2>&1 || error "jq not found"
}

############################
# PATH INITIALIZATION
############################

init_paths() {
    PCAP_BASENAME=$(basename "$PCAP" | sed 's/\.[^.]*$//')
    mkdir -p "$OUTDIR"

    EVE_JSON="${OUTDIR}/${PCAP_BASENAME}_eve.json"
    ALERTS_CSV="${OUTDIR}/${PCAP_BASENAME}_alerts.csv"
    DNS_CSV="${OUTDIR}/${PCAP_BASENAME}_dns.csv"
    HTTP_CSV="${OUTDIR}/${PCAP_BASENAME}_http.csv"
    TLS_CSV="${OUTDIR}/${PCAP_BASENAME}_tls.csv"
    FLOWS_CSV="${OUTDIR}/${PCAP_BASENAME}_flows.csv"
    TIMELINE_CSV="${OUTDIR}/${PCAP_BASENAME}_timeline.csv"
}

############################
# PCAP PROCESSING
############################

run_suricata() {
    log "Running Suricata on PCAP: $PCAP"

    TEMP_LOGDIR="${OUTDIR}/${PCAP_BASENAME}_suricata_tmp"
    mkdir -p "$TEMP_LOGDIR"

    CMD="suricata -r \"$PCAP\" -l \"$TEMP_LOGDIR\""

    if [ -n "$CUSTOM_RULES_FILE" ]; then
        log "Using custom rules file: $CUSTOM_RULES_FILE"
        CMD="$CMD -S \"$CUSTOM_RULES_FILE\""
    fi

    # Execute Suricata
    sh -c "$CMD" || error "Suricata failed"

    # Move eve.json to our designated output filename
    if [ -f "${TEMP_LOGDIR}/eve.json" ]; then
        mv "${TEMP_LOGDIR}/eve.json" "$EVE_JSON" || error "Failed to move eve.json"
        log "eve.json saved to $EVE_JSON"
    else
        error "eve.json not produced by Suricata"
    fi

    # Cleanup temporary folder
    rm -rf "$TEMP_LOGDIR"
}

verify_eve_json() {
    log "Verifying eve.json output"

    if [ ! -f "$EVE_JSON" ]; then
        error "eve.json not found at ${EVE_JSON}"
    fi
}

############################
# CSV EXPORT FUNCTIONS
############################

export_alerts_csv() {
    log "Exporting ${ALERTS_CSV}"

    # Write CSV header
    echo "timestamp,src_ip,src_port,dest_ip,dest_port,proto,alert_action,signature_id,signature,category,severity" > "$ALERTS_CSV"

    # Process eve.json line by line
    jq -r '
      select(.event_type=="alert") |
      [
        .timestamp,
        .src_ip,
        .src_port,
        .dest_ip,
        .dest_port,
        .proto,
        .alert.action,
        .alert.signature_id,
        .alert.signature,
        .alert.category,
        .alert.severity
      ] |
      @csv
    ' "$EVE_JSON" >> "$ALERTS_CSV"

    log "Alerts exported: $(wc -l < "$ALERTS_CSV") lines (including header)"
}


export_dns_csv() {
    log "Exporting ${DNS_CSV}"

    # CSV header
    echo "timestamp,src_ip,src_port,dest_ip,dest_port,proto,dns_type,id,rrname,rrtype,rcode,answers" > "$DNS_CSV"

    jq -r '
      select(.event_type=="dns") |
      .answers = (if .dns.answers then
                    (.dns.answers | map(.rdata) | join(";"))
                  else
                    ""
                  end) |
      [
        .timestamp,
        .src_ip,
        .src_port,
        .dest_ip,
        .dest_port,
        .proto,
        .dns.type,
        .dns.id,
        .dns.rrname,
        .dns.rrtype,
        .dns.rcode,
        .answers
      ] | @csv
    ' "$EVE_JSON" >> "$DNS_CSV"

    log "DNS events exported: $(wc -l < "$DNS_CSV") lines (including header)"
}

export_http_csv() {
    log "Exporting ${HTTP_CSV}"

    # CSV header
    echo "timestamp,src_ip,src_port,dest_ip,dest_port,proto,hostname,url,http_method,http_user_agent,status,length" > "$HTTP_CSV"

    jq -r '
      select(.event_type=="http") |
      [
        .timestamp,
        .src_ip,
        .src_port,
        .dest_ip,
        .dest_port,
        .proto,
        .http.hostname,
        .http.url,
        .http.http_method,
        .http.http_user_agent,
        .http.status,
        .http.length
      ] | @csv
    ' "$EVE_JSON" >> "$HTTP_CSV"

    log "HTTP events exported: $(wc -l < "$HTTP_CSV") lines (including header)"
}


export_tls_csv() {
    log "Exporting ${TLS_CSV}"

    echo "timestamp,src_ip,src_port,dest_ip,dest_port,proto,sni,version,ja3,issuerdn,subject,notbefore,notafter,fingerprint" > "$TLS_CSV"

    jq -r '
      select(.event_type=="tls") |
      [
        .timestamp,
        .src_ip,
        .src_port,
        .dest_ip,
        .dest_port,
        .proto,
        (.tls.sni // "" | if type=="object" or type=="array" then tostring else . end),
        (.tls.version // "" | if type=="object" or type=="array" then tostring else . end),
        (.tls.ja3 // "" | if type=="object" or type=="array" then tostring else . end),
        (.tls.issuerdn // "" | if type=="object" or type=="array" then tostring else . end),
        (.tls.subject // "" | if type=="object" or type=="array" then tostring else . end),
        (.tls.notbefore // "" | if type=="object" or type=="array" then tostring else . end),
        (.tls.notafter // "" | if type=="object" or type=="array" then tostring else . end),
        (.tls.fingerprint // "" | if type=="object" or type=="array" then tostring else . end)
      ] | @csv
    ' "$EVE_JSON" >> "$TLS_CSV"

    log "TLS events exported: $(wc -l < "$TLS_CSV") lines (including header)"
}




export_flows_csv() {
    log "Exporting ${FLOWS_CSV}"

    # CSV header
    echo "timestamp,src_ip,src_port,dest_ip,dest_port,proto,start,end,state,pkts_toserver,pkts_toclient,bytes_toserver,bytes_toclient,metadata,hash" > "$FLOWS_CSV"

    jq -r '
      select(.event_type=="flow") |
      [
        .timestamp,
        .src_ip,
        .src_port,
        .dest_ip,
        .dest_port,
        .proto,
        (.flow.start // "" | if type=="object" or type=="array" then tostring else . end),
        (.flow.end // "" | if type=="object" or type=="array" then tostring else . end),
        (.flow.state // "" | if type=="object" or type=="array" then tostring else . end),
        (.flow.pkts_toserver // ""),
        (.flow.pkts_toclient // ""),
        (.flow.bytes_toserver // ""),
        (.flow.bytes_toclient // ""),
        (.flow.metadata // "" | if type=="object" or type=="array" then tostring else . end),
        (.flow.hash // "" | if type=="object" or type=="array" then tostring else . end)
      ] | @csv
    ' "$EVE_JSON" >> "$FLOWS_CSV"

    log "Flow events exported: $(wc -l < "$FLOWS_CSV") lines (including header)"
}


export_ftp_csv() {
    FTP_CSV="${OUTDIR}/${PCAP_BASENAME}_ftp.csv"
    log "Exporting ${FTP_CSV}"

    # CSV header
    echo "timestamp,src_ip,src_port,dest_ip,dest_port,proto,command,command_data,command_truncated,completion_code,reply,reply_received,reply_truncated" > "$FTP_CSV"

    jq -r '
      select(.event_type=="ftp") |
      [
        .timestamp,
        .src_ip,
        .src_port,
        .dest_ip,
        .dest_port,
        .proto,
        .ftp.command // "",
        .ftp.command_data // "",
        (.ftp.command_truncated // null | if . == null then "" else tostring end),
        (.ftp.completion_code // [] | join(";")),
        (.ftp.reply // [] | join("|")),
        .ftp.reply_received // "",
        (.ftp.reply_truncated // null | if . == null then "" else tostring end)
      ] | @csv
    ' "$EVE_JSON" >> "$FTP_CSV"

    log "FTP events exported: $(wc -l < "$FTP_CSV") lines (including header)"
}




# -----------------------------------------------------------------------------
# export_timeline_csv()
#
# Generates a chronological CSV timeline of discrete Suricata events from eve.json.
# Only includes events with discrete, comparable timestamps:
#   - alert, dns, http, tls, ftp
# Flows or other aggregated statistics are intentionally excluded.
#
# Columns:
#   - timestamp       : Suricata event timestamp
#   - event_type      : Type of the event (alert, dns, http, tls, ftp)
#   - event_norm_data : Human-readable summary of the event:
#                        • alert → alert.signature
#                        • dns   → dns.rrname
#                        • http  → http.url
#                        • tls   → tls.sni
#                        • ftp   → ftp.command + ftp.command_data
#   - src_ip, src_port, dest_ip, dest_port, proto : Network endpoints
#   - extra           : JSON-encoded object containing all other event-specific fields
#
# Notes:
#   - Events are sorted chronologically by timestamp for easy timeline analysis.
#   - event_norm_data is positioned right after event_type for readability.
#   - extra preserves full event details without flattening, allowing deeper analysis.
#   - Fully portable: works on POSIX shells, WSL, Linux, and macOS.
# -----------------------------------------------------------------------------
export_timeline_csv() {
    TIMELINE_CSV="${OUTDIR}/${PCAP_BASENAME}_timeline.csv"
    log "Exporting ${TIMELINE_CSV}"

    # CSV header
    echo "timestamp,event_type,event_norm_data,src_ip,src_port,dest_ip,dest_port,proto,extra" > "$TIMELINE_CSV"

    jq -c '
      select(.event_type | IN("alert","dns","http","tls","ftp")) |
      {
        timestamp: .timestamp,
        event_type: .event_type,
        event_norm_data: (
          if .event_type=="alert" then (.alert.signature // "")
          elif .event_type=="dns" then (.dns.rrname // "")
          elif .event_type=="http" then (.http.url // "")
          elif .event_type=="tls" then (.tls.sni // "")
          elif .event_type=="ftp" then ((.ftp.command // "") + " " + (.ftp.command_data // ""))
          else ""
          end
        ),
        src_ip: (if .src_ip then .src_ip else "" end),
        src_port: (if .src_port then .src_port else "" end),
        dest_ip: (if .dest_ip then .dest_ip else "" end),
        dest_port: (if .dest_port then .dest_port else "" end),
        proto: (if .proto then .proto else "" end),
        extra: (del(.timestamp,.event_type,.event_norm_data,.src_ip,.src_port,.dest_ip,.dest_port,.proto) | @json)
      }
    ' "$EVE_JSON" | \
    sort | \
    jq -r '[.timestamp,.event_type,.event_norm_data,.src_ip,.src_port,.dest_ip,.dest_port,.proto,.extra] | @csv' >> "$TIMELINE_CSV"

    log "Timeline exported: $(wc -l < "$TIMELINE_CSV") lines (including header)"
}




############################
# MAIN EXECUTION FLOW
############################

main() {
    print_banner
    parse_args "$@"
    check_dependencies
    init_paths

    run_suricata
    verify_eve_json

    export_alerts_csv
    export_dns_csv
    export_http_csv
    export_ftp_csv
    export_tls_csv
    export_flows_csv
    export_timeline_csv

    log "pcap2csv complete"
    log "Output directory: $OUTDIR"
}

main "$@"
