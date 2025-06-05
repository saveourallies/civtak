#!/bin/bash

# Initial connection count
echo "Initial ESTABLISHED connections: $(netstat -tna | grep ESTABLISHED | wc -l)"

# Default LOG_FILE path
# Uses PWD to be relative to the directory where the script is called,
# which works better with sudo than using ~ for home directory.
DEFAULT_LOG_FILE="$PWD/ots/logs/opentakserver.log"

# Use provided log file path or default
LOG_FILE=${1:-$DEFAULT_LOG_FILE}

# --- Timing and State Variables ---
LAST_EMIT_TIMESTAMP=0
DETAILED_CHECK_QUEUED=0 # 0 for false, 1 for true
PERIODIC_SUMMARY_INTERVAL_SECONDS=$((15 * 60)) # 15 minutes
# last_periodic_summary_time will be initialized before the main loop
FREQUENT_E2E_CHECK_INTERVAL_SECONDS=30 # Check global e2e count every 30 seconds
last_frequent_e2e_check_time=0 # Will be initialized before the main loop

# Path to the new Python analyzer script (assuming it's in the same directory)
PYTHON_ANALYZER_SCRIPT="./ots_connection_analyzer.py"

# Associative array to store active E2E connections and their start times
declare -A ACTIVE_E2E_CONNECTIONS

# Delay for detailed check after last COT emit event (in seconds)
DETAILED_CHECK_DELAY_SECONDS=10 # Changed from 15

# Function to check if the log file exists
check_log_file() {
    if [ ! -f "$LOG_FILE" ]; then
        echo "Waiting for log file: $LOG_FILE" >&2
        return 1
    fi
    echo "Log file found: $LOG_FILE" >&2
    return 0
}

# Function to show TCP connection details using the Python script
# Takes an optional argument: "detailed" or "summary"
show_connection_details() {
    local mode="$1" # "summary" or "detailed"
    local python_output
    local current_time
    current_time=$(date +%s)

    if [ "$mode" == "summary" ]; then
        # For summary, we just get the count
        echo -e "\\n[FREQUENT STANDALONE LOCALHOST E2E COUNT CHECK (${FREQUENT_E2E_CHECK_INTERVAL_SECONDS}s)]" >&2
        # Suppress Python's stderr for summary mode
        python_output=$(python3 "$PYTHON_ANALYZER_SCRIPT" --mode e2e_count_only 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "Error running Python analyzer for count. Enable script's stderr for details." >&2
            return
        fi
        echo "Total ephemeral-to-ephemeral localhost connections: $python_output" >&2
    else # "detailed" mode
        echo -e "\\n[TCP CONNECTION ANALYSIS]" >&2
        echo "Running Python analyzer for detailed list (Python debug output suppressed)..." >&2
        
        declare -A SEEN_IN_THIS_RUN_E2E

        # Use process substitution to read from the Python script
        # This avoids creating a subshell for the while loop, so ACTIVE_E2E_CONNECTIONS is modified in the current shell
        while IFS= read -r line; do
            # The line below can be uncommented if you need to see the raw E2E_CONN lines from Python
            # echo "DEBUG_SHELL_PIPE: $line" >&2 

            if [[ "$line" == E2E_CONN:* ]]; then
                local conn_part="${line#E2E_CONN: }" 
                local conn_key_full="${conn_part%% | *}" 
                local python_pid_info="${conn_part#* | }"

                local safe_conn_key
                safe_conn_key=$(echo "$conn_key_full" | tr -d '[:space:]' | tr ':' '_' | tr '-' '_')

                SEEN_IN_THIS_RUN_E2E["$safe_conn_key"]=1

                if [ -z "${ACTIVE_E2E_CONNECTIONS[$safe_conn_key]}" ]; then
                    ACTIVE_E2E_CONNECTIONS["$safe_conn_key"]=$current_time
                    echo -e "[NEW E2E] $conn_key_full (PyPID: $python_pid_info) seen at $(date -d @"$current_time" +'%Y-%m-%d %H:%M:%S')" >&2
                    
                    local local_ip_port=$(echo "$conn_key_full" | awk '{print $1}')
                    local peer_ip_port=$(echo "$conn_key_full" | awk '{print $3}')
                    local l_port_num="${local_ip_port#*:}"
                    local p_port_num="${peer_ip_port#*:}"

                    echo "  Inspecting new E2E with ss: Local: $local_ip_port Peer: $peer_ip_port" >&2
                    local ss_output
                    # Attempt to find with original local/peer
                    ss_output=$(ss -Htnp "src 127.0.0.1:$l_port_num and dst 127.0.0.1:$p_port_num" 2>&1)
                    # If not found, try reversing, as the connection could be initiated from the other side
                    if [ -z "$ss_output" ]; then
                        ss_output=$(ss -Htnp "src 127.0.0.1:$p_port_num and dst 127.0.0.1:$l_port_num" 2>&1)
                    fi

                    if [ -n "$ss_output" ]; then
                        # Indent ss_output for readability
                        echo "$ss_output" | sed 's/^/  SS_INFO: /' >&2
                    else
                        echo "  SS_INFO: Could not find specific connection details with ss for $local_ip_port <-> $peer_ip_port." >&2
                    fi
                else
                    local start_time=${ACTIVE_E2E_CONNECTIONS[$safe_conn_key]}
                    local age=$((current_time - start_time))
                    # Note: Changed (PID: ...) to (PyPID: ...) here as well for consistency
                    echo -e "[ACTIVE E2E] $conn_key_full (PyPID: $python_pid_info) open for ${age}s (since $(date -d @"$start_time" +'%Y-%m-%d %H:%M:%S'))" >&2
                fi
            fi
        done < <(python3 "$PYTHON_ANALYZER_SCRIPT" --mode detailed_list 2>/dev/null) # Process substitution here
        
        # Check for closed connections
        for key in "${!ACTIVE_E2E_CONNECTIONS[@]}"; do
            if [ -z "${SEEN_IN_THIS_RUN_E2E[$key]}" ]; then
                local start_time=${ACTIVE_E2E_CONNECTIONS[$key]}
                local open_duration=$((current_time - start_time))
                local display_key_approx
                display_key_approx=$(echo "$key" | sed 's/_[0-9]*_/:/g' | sed 's/_->_/ -> /g')
                echo -e "[CLOSED E2E] $display_key_approx was open for ${open_duration}s (from $(date -d @"$start_time" +'%Y-%m-%d %H:%M:%S'))" >&2
                unset ACTIVE_E2E_CONNECTIONS["$key"]
            fi
        done

        echo "Python analyzer processing in shell completed." >&2 # Changed message slightly
        echo "[END TCP CONNECTION ANALYSIS]" >&2
    fi
}

# Wait for log file to exist
until check_log_file; do
    sleep 5
done

echo "Starting to monitor OTS logs from: $LOG_FILE"
echo "Connection analysis will be performed using $PYTHON_ANALYZER_SCRIPT."
echo "Summary check every $PERIODIC_SUMMARY_INTERVAL_SECONDS seconds. Detailed check 10s after last COT emit."

exec 3< <(tail -F --pid=$$ -n0 "$LOG_FILE")
TAIL_PID=$!

trap_handler() {
    echo "Signal received. Stopping tail (PID $TAIL_PID) and cleaning up..." >&2
    if [[ -n "$TAIL_PID" ]] && kill -0 "$TAIL_PID" 2>/dev/null; then
        if kill -TERM "$TAIL_PID" 2>/dev/null; then
            for _ in 1 2 3; do
                if ! kill -0 "$TAIL_PID" 2>/dev/null; then
                    echo "Tail process $TAIL_PID terminated gracefully." >&2
                    TAIL_PID=""
                    break
                fi
                sleep 1
            done
        fi
    fi
    if [[ -n "$TAIL_PID" ]] && kill -0 "$TAIL_PID" 2>/dev/null; then
        echo "Tail process $TAIL_PID did not terminate with SIGTERM. Sending SIGKILL..." >&2
        kill -KILL "$TAIL_PID" 2>/dev/null
    fi
    echo "Closing log file descriptor (FD 3)..." >&2
    exec 3<&-
    echo "Exiting script now." >&2
    exit 0
}
trap trap_handler EXIT INT TERM

echo "Monitoring started. Log read timeout: 5 seconds. Periodic summary interval: $PERIODIC_SUMMARY_INTERVAL_SECONDS seconds." >&2
echo "Detailed check after COT emit quiescence: $DETAILED_CHECK_DELAY_SECONDS seconds."

last_periodic_summary_time=$(date +%s)
last_frequent_e2e_check_time=$(date +%s)

while true; do
    if IFS= read -r -t 5 line <&3; then
        if echo "$line" | grep -q "'ClientController' object has no attribute 'rabbit_connection'"; then continue; fi
        if echo "$line" | grep -q "NO_SHARED_CIPHER"; then continue; fi
        if echo "$line" | grep -q "UNSUPPORTED_PROTOCOL"; then continue; fi
        if echo "$line" | grep -q "BAD_KEY_SHARE"; then continue; fi
        if echo "$line" | grep -q "Failed to do handshake: \[Errno 104\] Connection reset by peer"; then continue; fi

        echo "[LOG] $line" >&2

        if echo "$line" | grep -q "Connection from"; then
            connection_info=$(echo "$line" | grep -o "Connection from.*")
            echo -e "\n[OTS EVENT] $connection_info" >&2 
        fi

        if echo "$line" | grep -q "OpenTAKServer.*emitting event .* to all"; then
            LAST_EMIT_TIMESTAMP=$(date +%s)
            DETAILED_CHECK_QUEUED=1
            echo -e "\n[OTS EMIT DETECTED] Noted at $LAST_EMIT_TIMESTAMP. Detailed check will occur 10s after last emit." >&2
        fi

        if echo "$line" | grep -qE '<event|<cot|takControl|takServer'; then
            summary=$(echo "$line" | grep -oE '<event[^>]*>|<cot[^>]*>|<takControl[^>]*>|<takServer[^>]*>')
            callsigns=$(echo "$line" | grep -oE 'callsign="[^"]*"' | sed 's/callsign=//g' | tr -d '"' | paste -sd ',' -)
            if [ -n "$callsigns" ]; then summary="$summary callsigns=$callsigns"; fi
            echo "[COT SUMMARY] $summary" >&2
        fi
    else
        CURRENT_TIME=$(date +%s)

        if [ "$DETAILED_CHECK_QUEUED" -eq 1 ]; then
            if (( (CURRENT_TIME - LAST_EMIT_TIMESTAMP) >= DETAILED_CHECK_DELAY_SECONDS )); then
                echo -e "\n[OTS EMIT QUIESCENCE (${DETAILED_CHECK_DELAY_SECONDS}s)] Triggering DETAILED connection analysis..." >&2
                show_connection_details "detailed" # Calls python script with --mode detailed_list
                DETAILED_CHECK_QUEUED=0
            fi
        fi

        if (( (CURRENT_TIME - last_periodic_summary_time) >= PERIODIC_SUMMARY_INTERVAL_SECONDS )); then
            echo -e "\n[PERIODIC SUMMARY CHECK (${PERIODIC_SUMMARY_INTERVAL_SECONDS}s)]" >&2
            show_connection_details "summary" # Calls python script with --mode e2e_count_only
            last_periodic_summary_time=$CURRENT_TIME
        fi
        
        if (( (CURRENT_TIME - last_frequent_e2e_check_time) >= FREQUENT_E2E_CHECK_INTERVAL_SECONDS )); then
            echo -e "\n[FREQUENT STANDALONE LOCALHOST E2E COUNT CHECK (${FREQUENT_E2E_CHECK_INTERVAL_SECONDS}s)]" >&2
            show_connection_details "summary" # Calls python script with --mode e2e_count_only
            last_frequent_e2e_check_time=$CURRENT_TIME
        fi
    fi
done 