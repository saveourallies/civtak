#!/bin/bash

# Default path for the known ports INI file
DEFAULT_KNOWN_PORTS_INI="./knownports.ini"
KNOWN_PORTS_INI=""
PYTHON_ANALYZER_SCRIPT="./ots_connection_analyzer.py" # Path to the python script

# Function to show usage
usage() {
    echo "Usage: $0 [-a] [-p port_number] [-k known_ports_file.ini]"
    echo "  -a : Analyze all connections (E2E and Service Ports)."
    echo "  -p : Specify a service port number to get detailed stats for that port."
    echo "  -k : Specify a known_ports.ini file (default: ${DEFAULT_KNOWN_PORTS_INI})."
    exit 1
}

# Function to check for jq
check_jq() {
    if ! command -v jq &> /dev/null; then
        echo "Error: jq is not installed. Please install jq to use this script."
        echo "On Debian/Ubuntu: sudo apt-get install jq"
        echo "On CentOS/RHEL: sudo yum install jq"
        echo "On macOS (Homebrew): brew install jq"
        exit 1
    fi
}

# Function to check for lsof
check_lsof() {
    if ! command -v lsof &> /dev/null; then
        echo "Error: lsof is not installed. Please install lsof to use this script."
        echo "On Debian/Ubuntu: sudo apt-get install lsof"
        echo "On CentOS/RHEL: sudo yum install lsof"
        echo "On macOS (Homebrew): brew install lsof"
        exit 1
    fi
}

# Function to get E2E connections using the Python script
get_e2e_connections() {
    local ini_file_to_use="${KNOWN_PORTS_INI:-$DEFAULT_KNOWN_PORTS_INI}"
    echo "Ephemeral-to-Ephemeral (E2E) Connections (via Python Analyzer)"
    echo "----------------------------------------------------------------------"
    if [ ! -f "$PYTHON_ANALYZER_SCRIPT" ]; then
        echo "Error: Python analyzer script not found at $PYTHON_ANALYZER_SCRIPT" >&2
        return
    fi
    if [ ! -f "$ini_file_to_use" ] && [ "$ini_file_to_use" == "$DEFAULT_KNOWN_PORTS_INI" ]; then
        echo "Warning: Default known_ports.ini not found at $DEFAULT_KNOWN_PORTS_INI. Python script might use its internal defaults or report an error." >&2
        # Allow script to proceed, python script handles its own default/error for missing ini
    fi

    json_output=$($PYTHON_ANALYZER_SCRIPT --mode json_e2e_details_once --known-ports-file "$ini_file_to_use" 2>/dev/null)
    exit_status=$?

    if [ $exit_status -ne 0 ]; then
        echo "Error: Python analyzer script failed. Exit status: $exit_status" >&2
        echo "Ensure '$PYTHON_ANALYZER_SCRIPT' is executable and all its dependencies are met." >&2
        # Attempt to capture stderr from python script if possible, though it was redirected above
        # For now, just a general error message.
        return
    fi

    if [ -z "$json_output" ] || ! echo "$json_output" | jq -e . > /dev/null 2>&1; then
        echo "Error: Python script returned no valid JSON output or an empty response." >&2
        echo "Python script output was: $json_output" >&2 # Show what was (not) returned
        return
    fi

    e2e_count=$(echo "$json_output" | jq 'length')
    echo "Total E2E connections found by Python analyzer: $e2e_count"

    if [ "$e2e_count" -gt 0 ]; then
        # Read all json objects into an array for pairing
        mapfile -t e2e_lines < <(echo "$json_output" | jq -c '.[]')
        
        processed_indices=()

        for i in "${!e2e_lines[@]}"; do
            # Check if this index has been processed as a counterpart already
            if [[ " ${processed_indices[*]} " =~ " ${i} " ]]; then
                continue
            fi

            line1="${e2e_lines[$i]}"
            label1=$(echo "$line1" | jq -r '.label')
            local_addr1=$(echo "$line1" | jq -r '.local_addr')
            peer_addr1=$(echo "$line1" | jq -r '.peer_addr')
            pid1=$(echo "$line1" | jq -r '.pid // "N/A"')
            proc_name1=$(echo "$line1" | jq -r '.process_name // "N/A"')
            proc_start1=$(echo "$line1" | jq -r '.process_start_time // "N/A"')
            is_localhost1=$(echo "$line1" | jq -r '.is_localhost_both_sides')

            # Try to find counterpart E2E-B-A for E2E-A-B
            # Extract ports from label1: E2E-PORTA-PORTB
            port_a=$(echo "$label1" | cut -d'-' -f2)
            port_b=$(echo "$label1" | cut -d'-' -f3)
            expected_counterpart_label="E2E-$port_b-$port_a"
            
            found_counterpart=false
            counterpart_index=-1

            for j in "${!e2e_lines[@]}"; do
                if [ $i -eq $j ]; then continue; fi # Skip self
                if [[ " ${processed_indices[*]} " =~ " ${j} " ]]; then continue; fi # Skip already processed

                line2_label=$(echo "${e2e_lines[$j]}" | jq -r '.label')
                if [ "$line2_label" == "$expected_counterpart_label" ]; then
                    found_counterpart=true
                    counterpart_index=$j
                    break
                fi
            done
            
            echo ""
            printf "  %-18s: %s\n" "Label" "$label1"
            printf "  %-18s: %s\n" "Local Address" "$local_addr1"
            printf "  %-18s: %s\n" "Peer Address" "$peer_addr1"
            printf "  %-18s: %s\n" "PID" "$pid1"
            printf "  %-18s: %s\n" "Process Name" "$proc_name1"
            printf "  %-18s: %s\n" "Process Start" "$proc_start1"
            if [ "$is_localhost1" = "false" ]; then
                printf "  %-18s: Connection NOT strictly 127.0.0.1 on both sides.\n" "Note"
            fi
            processed_indices+=("$i")

            if $found_counterpart; then
                line2="${e2e_lines[$counterpart_index]}"
                label2=$(echo "$line2" | jq -r '.label')
                local_addr2=$(echo "$line2" | jq -r '.local_addr')
                peer_addr2=$(echo "$line2" | jq -r '.peer_addr')
                pid2=$(echo "$line2" | jq -r '.pid // "N/A"')
                proc_name2=$(echo "$line2" | jq -r '.process_name // "N/A"')
                proc_start2=$(echo "$line2" | jq -r '.process_start_time // "N/A"')
                is_localhost2=$(echo "$line2" | jq -r '.is_localhost_both_sides')
                
                echo "  -- Counterpart --"
                printf "  %-18s: %s\n" "Label" "$label2"
                printf "  %-18s: %s\n" "Local Address" "$local_addr2"
                printf "  %-18s: %s\n" "Peer Address" "$peer_addr2"
                printf "  %-18s: %s\n" "PID" "$pid2"
                printf "  %-18s: %s\n" "Process Name" "$proc_name2"
                printf "  %-18s: %s\n" "Process Start" "$proc_start2"
                if [ "$is_localhost2" = "false" ]; then
                    printf "  %-18s: Connection NOT strictly 127.0.0.1 on both sides.\n" "Note"
                fi
                processed_indices+=("$counterpart_index")
            else
                # Extract ports from label1 again to show what was expected for the counterpart note
                port_a_note=$(echo "$label1" | cut -d'-' -f2)
                port_b_note=$(echo "$label1" | cut -d'-' -f3)
                expected_counterpart_label_note="E2E-$port_b_note-$port_a_note"
                printf "  %-18s: Direct counterpart (%s) not found for %s in this batch.\n" "Note" "$expected_counterpart_label_note" "$label1"
            fi
        done

        # Add totals by Process Name
        echo ""
        echo "E2E Totals by Process Name:"
        echo "-----------------------------"
        # Create an associative array for process name counts
        declare -A process_counts
        for line in "${e2e_lines[@]}"; do
            proc_name=$(echo "$line" | jq -r '.process_name // "N/A"')
            ((process_counts[$proc_name]++))
        done

        if [ ${#process_counts[@]} -gt 0 ]; then
            for name in "${!process_counts[@]}"; do
                printf "  %-30s : %3d E2E connections\n" "$name" "${process_counts[$name]}"
            done
        else
            echo "  No process names found or all were N/A."
        fi

    else
        echo "No E2E connections reported by Python analyzer."
    fi
    echo "----------------------------------------------------------------------"
    echo ""
}


# Function to count connections for specific service ports
count_service_port_connections() {
    local target_port=$1 # If a specific port is passed
    local ini_file_to_use="${KNOWN_PORTS_INI:-$DEFAULT_KNOWN_PORTS_INI}"
    local service_ports_list=()

    if [ -f "$ini_file_to_use" ]; then
        # Read ports from INI - basic parsing, assumes simple comma separated list
        ports_str=$(grep -E '^[[:space:]]*ports[[:space:]]*=' "$ini_file_to_use" | sed -E 's/^[[:space:]]*ports[[:space:]]*=[[:space:]]*//' | tr -d '[:space:]')
        IFS=',' read -ra service_ports_list <<< "$ports_str"
        if [ ${#service_ports_list[@]} -eq 0 ]; then 
            echo "Warning: No ports parsed from $ini_file_to_use for service port counting." >&2
        fi
    else
        echo "Warning: Known ports INI file not found at $ini_file_to_use for service port counting." >&2
        echo "Service port counting will be skipped unless a specific port is provided with -p." >&2
        if [ -z "$target_port" ]; then # Only skip if -a mode and no INI
             return
        fi
    fi

    echo "Service Port Connections (from lsof)"
    echo "-------------------------------------------------------"

    if [ -n "$target_port" ]; then # Specific port given with -p
        if [[ ! " ${service_ports_list[@]} " =~ " ${target_port} " ]] && [ ${#service_ports_list[@]} -gt 0 ]; then
             echo "Note: Port $target_port was not listed in $ini_file_to_use. Analyzing it anyway." >&2
        fi
        service_ports_to_analyze=("$target_port")
    elif [ ${#service_ports_list[@]} -gt 0 ]; then # -a mode, use ports from INI
        service_ports_to_analyze=("${service_ports_list[@]}")
    else # -a mode, but no INI and no ports parsed
        echo "No service ports to analyze (INI file missing or empty, and no -p specified)." >&2
        return
    fi
    
    for port_to_check in "${service_ports_to_analyze[@]}"; do
        if ! [[ "$port_to_check" =~ ^[0-9]+$ ]]; then
            echo "Skipping invalid port from INI: $port_to_check" >&2
            continue
        fi
        echo "Analyzing connections for service port $port_to_check:"
        # Use lsof to get connections. -iTCP selects TCP, -sTCP:ESTABLISHED filters for established.
        # Grep for lines where the local port is $port_to_check (e.g., *:port_to_check or 127.0.0.1:port_to_check)
        # Using a more robust grep for the port, considering IPv4 and IPv6, and ensuring it's the port number.
        # The regex looks for the port number preceded by a colon and followed by a space or ->
        established_connections=$(sudo lsof -i TCP:"$port_to_check" -s TCP:ESTABLISHED -nP -a)
        total=$(echo "$established_connections" | sed 1d | wc -l) # sed 1d to remove lsof header
        
        echo "  Total connections to port $port_to_check: $total"
        if [ "$total" -gt 0 ]; then
            echo "    Connection breakdown by source IP (Remote Address):"
            echo "$established_connections" | sed 1d | awk '{print $9}' | awk -F'[:->]' '{gsub(/^[[:space:]]+|[[:space:]]+$/, "", $(NF-1)); print $(NF-1)}' | sort | uniq -c | sort -rn | \
                while read count ip; do
                    # Handle cases where awk might produce empty ip if $9 is not as expected
                    if [ -n "$ip" ]; then
                         printf "      %-20s : %3d connections\n" "$ip" "$count"
                    fi
                done

            echo "    Connection breakdown by Process Command Name:"
            echo "$established_connections" | sed 1d | awk '{cmd=$1; for(i=10;i<=NF;i++) cmd=cmd" "$i; print cmd}' | awk '{$1=$1; print $1}' | sort | uniq -c | sort -rn | \
                while read count cmd_name; do
                    # Handle cases where awk might produce empty cmd_name
                    if [ -n "$cmd_name" ]; then
                         printf "      %-30s : %3d connections\n" "$cmd_name" "$count"
                    fi
                done
        fi
        echo ""
    done
    echo "-------------------------------------------------------"
}

# Parse command line arguments
check_jq # Ensure jq is available first
check_lsof # Ensure lsof is available

while getopts "ap:k:" opt; do
    case $opt in
        a)
            MODE="all"
            ;;
        p)
            SPECIFIC_PORT=$OPTARG
            MODE="specific_port"
            ;;
        k)
            KNOWN_PORTS_INI=$OPTARG
            ;;
        *)
            usage
            ;;
    esac
done

# Determine ini_file_path for Python script and service port counting
ini_file_to_use="${KNOWN_PORTS_INI:-$DEFAULT_KNOWN_PORTS_INI}"
if [ -n "$KNOWN_PORTS_INI" ] && [ ! -f "$KNOWN_PORTS_INI" ]; then
    echo "Error: Specified known_ports.ini file not found: $KNOWN_PORTS_INI" >&2
    exit 1
elif [ -z "$KNOWN_PORTS_INI" ] && [ ! -f "$DEFAULT_KNOWN_PORTS_INI" ]; then
    echo "Warning: Default known_ports.ini ($DEFAULT_KNOWN_PORTS_INI) not found. Service port analysis might be limited." >&2
    # E2E will still run, as python script handles its own ini defaults/errors.
fi


if [ "$MODE" == "all" ]; then
    echo "Analyzing ALL connections (E2E via Python, Service Ports via lsof)..."
    echo "Using known ports INI: $ini_file_to_use"
    echo "======================================================================"
    get_e2e_connections # This function will use $ini_file_to_use implicitly via global or default
    count_service_port_connections # This function also uses $ini_file_to_use implicitly
    echo "======================================================================"
    echo "Analysis complete."
    exit 0
elif [ "$MODE" == "specific_port" ]; then
    echo "Analyzing specific service port $SPECIFIC_PORT (via lsof)..."
    echo "Using known ports INI: $ini_file_to_use for context if port is in INI."
    echo "======================================================================"
    count_service_port_connections "$SPECIFIC_PORT"
    echo "======================================================================"
    echo "Analysis for port $SPECIFIC_PORT complete."
    exit 0
fi

# If no valid mode determined or no options provided after getopts
if [ $OPTIND -eq 1 ] && [ -z "$MODE" ]; then
    usage
fi

# Fallback if only -k was provided without -a or -p (OPTIND > 1 but MODE not set)
if [ -z "$MODE" ]; then
    echo "Error: -k option must be used with -a or -p." >&2
    usage
fi 