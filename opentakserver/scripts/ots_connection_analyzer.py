#!/usr/bin/env python3
import subprocess
import re
from collections import Counter
import argparse
import sys
import time
import os
import select
import signal
import configparser
import json

# Default path for the known ports INI file
DEFAULT_KNOWN_PORTS_FILE = "./knownports.ini"
KNOWN_PORTS_TO_EXCLUDE = [] # Will be populated from INI file or defaults

# --- Constants for monitoring mode ---
DEFAULT_LOG_FILE = "./ots/logs/opentakserver.log" # Example, adjust as needed
# DEFAULT_PERIODIC_SUMMARY_INTERVAL_SECONDS = 15 * 60 # Removed
# DEFAULT_FREQUENT_E2E_CHECK_INTERVAL_SECONDS = 30 # Removed
DEFAULT_DETAILED_CHECK_DELAY_SECONDS = 1
OTS_EMIT_REGEX = re.compile(r"OpenTAKServer.*emitting event .* to all") # Basic regex for emit

# Regex to identify log lines that are likely to contain full COT XML payloads
COT_XML_PAYLOAD_REGEX = re.compile(r"client_controller - run - \d+ - DEBUG - b'.*?<event")

# Regex for RabbitMQ consumer creation/activity - USER MAY NEED TO REFINE THIS
RABBITMQ_CONSUMER_REGEX = re.compile(r"AMQP_CLIENT|RabbitMQ consumer|creating consumer for|consumer \[", re.IGNORECASE)

# Regex for our specific PyTAK client connection event
PYTAK_CLIENT_CONNECT_REGEX = re.compile(r".*PYTAK_CLIENT_CONNECT_EVENT: UID=([^,]+), Callsign=([^,]+), IP=([^\s]+)")

INTERESTING_CLIENT_PATTERNS = {
    "PyTAK_Client_informs1": re.compile(r"informs1", re.IGNORECASE),
    "PyTAK_Client_informsqa": re.compile(r"informsqa", re.IGNORECASE),
    "ATAK_iTAK_Client_kdtzipad": re.compile(r"KDTZipad", re.IGNORECASE),
    "ATAK_iTAK_Client_farts": re.compile(r"farts", re.IGNORECASE),
    # Add other specific client identifiers if known
}

# --- Global state for monitoring (consider encapsulating in a class later if it grows) ---
ACTIVE_E2E_CONNECTIONS = {} # Stores e2e_key: {start_time: timestamp, netstat_info: str}
ACTIVE_SERVICE_CONNECTIONS = {} # Stores service_conn_key: {start_time: timestamp, ephemeral_port: int, service_port: int, details: str}
# LAST_EMIT_TIMESTAMP, DETAILED_CHECK_QUEUED, LAST_TRIGGERING_EVENT_INFO, LAST_POTENTIAL_COT_MESSAGE
# will be managed locally within monitor_log_and_analyze
# --- End Global State ---

# --- Global state for correlating PyTAK client connects with E2E conn creations ---
RECENTLY_CONNECTED_PYTAK_CLIENTS = [] # Stores dicts: {'uid': ..., 'callsign': ..., 'ip': ..., 'time': timestamp}
PYTAK_EVENT_CORRELATION_WINDOW_SECONDS = 15 # How long to consider a PyTAK event relevant

def load_known_ports(filepath):
    """Loads known ports from an INI file."""
    ports = []
    try:
        parser = configparser.ConfigParser()
        if os.path.exists(filepath):
            parser.read(filepath)
            if 'ServicePorts' in parser and 'ports' in parser['ServicePorts']:
                ports_str = parser['ServicePorts']['ports']
                ports = [int(p.strip()) for p in ports_str.split(',') if p.strip().isdigit()]
                print(f"INFO: Loaded {len(ports)} known ports from {filepath}: {ports}", file=sys.stderr)
            else:
                print(f"WARNING: 'ServicePorts' section or 'ports' key not found in {filepath}. Using empty known_ports list.", file=sys.stderr)
        else:
            print(f"WARNING: Known ports file not found: {filepath}. Using empty known_ports list.", file=sys.stderr)
    except Exception as e:
        print(f"ERROR: Could not read known ports file {filepath}: {e}. Using empty known_ports list.", file=sys.stderr)
    
    # Fallback to a minimal default if file is absent or parsing fails and ports list is empty
    if not ports:
        default_ports_fallback = [22, 5672] # Minimal default
        print(f"INFO: Using fallback default known ports: {default_ports_fallback}", file=sys.stderr)
        return default_ports_fallback
    return ports

def tail_log_file(log_path):
    """
    Continuously tails a log file, yielding new lines.
    Uses `tail -F -n0` for robust following.
    """
    print(f"INFO: Starting to tail log file: {log_path}", file=sys.stderr)
    try:
        process = subprocess.Popen(['tail', '-F', '-n0', log_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Ensure the tail process can be terminated
        def cleanup_tail(signum, frame):
            print(f"INFO: Terminating tail process ({process.pid})...", file=sys.stderr)
            process.terminate()
            process.wait()
            sys.exit(0)

        # Register signal handlers for cleanup if the main script is killed
        # This might be redundant if the main script's signal handler also kills children,
        # but good for direct testing of this function or if it runs more independently.
        # signal.signal(signal.SIGINT, cleanup_tail)
        # signal.signal(signal.SIGTERM, cleanup_tail)

        poller = select.poll()
        poller.register(process.stdout, select.POLLIN)

        while True:
            if poller.poll(1000): # Timeout of 1 second
                line = process.stdout.readline()
                if line:
                    yield line.strip()
                elif process.poll() is not None: # Process terminated
                    print(f"WARNING: Tail process for {log_path} terminated.", file=sys.stderr)
                    break # Exit if tail process dies
            # Check for stderr output from tail occasionally (optional)
            # if process.stderr.readable():
            #     err_line = process.stderr.readline()
            #     if err_line:
            #         print(f"TAIL_STDERR: {err_line.strip()}", file=sys.stderr)

    except FileNotFoundError:
        print(f"ERROR: 'tail' command not found. Please ensure it's installed.", file=sys.stderr)
        return # Or raise an exception
    except Exception as e:
        print(f"ERROR: Exception in tail_log_file for {log_path}: {e}", file=sys.stderr)
        return # Or raise
    finally:
        if 'process' in locals() and process.poll() is None:
            print(f"INFO: Cleaning up tail process ({process.pid}) from tail_log_file finally block.", file=sys.stderr)
            process.terminate()
            process.wait()

def inspect_e2e_connection_with_ss(local_port, peer_port):
    """
    Uses ss to get details about a specific localhost E2E connection.
    Returns a tuple: (ss_output_string, process_pid_str, process_start_time_str, process_name_str).
    """
    if not isinstance(local_port, (int, str)) or not isinstance(peer_port, (int, str)):
        return "SS_INFO: Invalid port types for ss inspection.", "N/A", "N/A", "N/A"

    ss_output_lines = []
    raw_ss_output = ""
    process_pid_str = "N/A"
    process_name_str = "N/A"
    process_start_time_str = "N/A"

    try:
        # Try direct match with sudo
        cmd1 = ['sudo', 'ss', '-Htnp', f"( src 127.0.0.1:{local_port} and dst 127.0.0.1:{peer_port} )"]
        result1 = subprocess.run(cmd1, capture_output=True, text=True, check=False, timeout=2)
        if result1.stdout.strip():
            raw_ss_output = result1.stdout.strip()
            ss_output_lines.append(raw_ss_output)
        
        # Try reverse match with sudo
        if not ss_output_lines:
            cmd2 = ['sudo', 'ss', '-Htnp', f"( src 127.0.0.1:{peer_port} and dst 127.0.0.1:{local_port} )"]
            result2 = subprocess.run(cmd2, capture_output=True, text=True, check=False, timeout=2)
            if result2.stdout.strip():
                raw_ss_output = result2.stdout.strip() # Use this one if cmd1 was empty
                ss_output_lines.append(raw_ss_output)

        # Attempt to parse PID and Name from raw_ss_output
        if raw_ss_output:
            pid_match = re.search(r'pid=(\d+)', raw_ss_output)
            name_match = re.search(r'users:\(\(("[^\"]+"),pid=\d+', raw_ss_output)
            if pid_match:
                process_pid_str = pid_match.group(1)
                if name_match:
                    process_name_str = name_match.group(1).strip('"')
                else:
                    process_name_str = "N/A"
                try:
                    # No sudo here for ps, as it's just querying based on PID we already got (potentially via sudo ss)
                    ps_cmd = ['ps', '-o', 'lstart', '--no-headers', '-p', process_pid_str]
                    ps_result = subprocess.run(ps_cmd, capture_output=True, text=True, check=True, timeout=1)
                    process_start_time_str = ps_result.stdout.strip()
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
                    process_start_time_str = "ErrorFetching"
        
        if ss_output_lines:
            return "\n".join(ss_output_lines), process_pid_str, process_start_time_str, process_name_str
        else:
            return f"SS_INFO: No details found with ss for 127.0.0.1:{local_port} <-> 127.0.0.1:{peer_port}", "N/A", "N/A", "N/A"

    except subprocess.TimeoutExpired:
        return f"SS_INFO: Timeout inspecting 127.0.0.1:{local_port} <-> 127.0.0.1:{peer_port}", "N/A", "N/A", "N/A"
    except FileNotFoundError:
        # This could be sudo, ss, or ps not found
        return "SS_INFO: 'sudo', 'ss' or 'ps' command not found for inspection.", "N/A", "N/A", "N/A"
    except Exception as e:
        return f"SS_INFO: Error inspecting with ss/ps: {e}", "N/A", "N/A", "N/A"

def get_raw_connections():
    """
    Gets connection data using netstat -tna.
    Returns a list of ESTABLISHED tcp connection lines and the type 'netstat',
    or an empty list and None if it fails.
    """
    try:
        print("DEBUG_PY_RAW: Attempting 'netstat -tna'", file=sys.stderr)
        result_netstat = subprocess.run(['netstat', '-tna'], capture_output=True, text=True, check=False)
        print(f"DEBUG_PY_RAW: 'netstat -tna' | RC: {result_netstat.returncode}", file=sys.stderr)
        
        if result_netstat.returncode == 0 and result_netstat.stdout.strip():
            established_lines = [
                line for line in result_netstat.stdout.strip().split('\n') 
                if 'ESTABLISHED' in line and line.startswith('tcp')
            ]
            if established_lines:
                print(f"DEBUG_PY_RAW: 'netstat -tna' | Found {len(established_lines)} ESTABLISHED tcp lines. First line (if any): {established_lines[0] if established_lines else 'N/A'}", file=sys.stderr)
                return established_lines, "netstat"
            else:
                print("DEBUG_PY_RAW: 'netstat -tna' | No ESTABLISHED tcp lines found in output.", file=sys.stderr)
                print(f"DEBUG_PY_RAW: 'netstat -tna' | Full STDOUT (first 300 chars): {result_netstat.stdout.strip()[:300]}", file=sys.stderr)
                return [], None # No established lines found
        elif result_netstat.stderr.strip():
            print(f"DEBUG_PY_RAW: 'netstat -tna' | STDERR: {result_netstat.stderr.strip()}", file=sys.stderr)
            return [], None # Error occurred
        else: # Command ran, returned 0, but stdout was empty
            print("DEBUG_PY_RAW: 'netstat -tna' | Command successful but no output.", file=sys.stderr)
            return [], None

    except FileNotFoundError:
        print("DEBUG_PY_RAW: 'netstat' command not found.", file=sys.stderr)
        return [], None
    except Exception as e:
        print(f"DEBUG_PY_RAW: Exception running 'netstat -tna': {e}", file=sys.stderr)
        return [], None
        
    # This part should ideally not be reached if netstat fails and returns [], None above.
    # However, as a final fallback, ensure we always return a tuple.
    print("DEBUG_PY_RAW: Fallback - All methods to get connections failed to produce output.", file=sys.stderr)
    return [], None

def parse_connections(raw_lines, conn_type):
    parsed_connections = []
    # Simplified regex for IPv4 localhost:port
    ip_port_regex = re.compile(r"(127\.0\.0\.1):([0-9]+)")

    print(f"DEBUG_PY_PARSE: Entering parse_connections for type '{conn_type}'. Processing {len(raw_lines)} raw lines.", file=sys.stderr)
    print(f"DEBUG_PY_PARSE: Using simplified regex for IPv4 localhost: {ip_port_regex.pattern}", file=sys.stderr)

    for line_num, line in enumerate(raw_lines):
        parts = line.split()
        process_info_str = "N/A"
        # print(f"DEBUG_PY_PARSE: Raw line {line_num+1}: '{line}'", file=sys.stderr) # Can be too verbose, enable if needed

        try:
            local_addr_port = None
            peer_addr_port = None

            if conn_type == "ss_p":
                if len(parts) < 4: # Need at least Recv-Q, Send-Q, Local, Peer
                    # print(f"DEBUG_PY_PARSE: ss_p line {line_num+1} too short: '{line}'", file=sys.stderr)
                    continue
                local_addr_port = parts[2] # Recv-Q, Send-Q, Local-Addr:Port, Peer-Addr:Port, Process
                peer_addr_port = parts[3]
                if len(parts) > 4: # Process info is parts[4] onwards
                    process_info_str = " ".join(parts[4:])
            elif conn_type == "ss":
                if len(parts) < 4: # Need at least Recv-Q, Send-Q, Local, Peer
                    # print(f"DEBUG_PY_PARSE: ss line {line_num+1} too short: '{line}'", file=sys.stderr)
                    continue
                local_addr_port = parts[2] # Recv-Q, Send-Q, Local-Addr:Port, Peer-Addr:Port
                peer_addr_port = parts[3]
            elif conn_type == "netstat":
                # print(f"DEBUG_PY_PARSE: Processing netstat line {line_num+1}: '{line}'", file=sys.stderr) # Verbose
                if len(parts) < 5: 
                    # print(f"DEBUG_PY_PARSE: netstat line {line_num+1} too short: '{line}'", file=sys.stderr)
                    continue
                local_addr_port = parts[3]
                peer_addr_port = parts[4]
                if len(parts) > 6 and parts[5] == "ESTABLISHED" and parts[6] != '-':
                     process_info_str = parts[6]
                elif len(parts) > 5 and parts[5] != "ESTABLISHED" and parts[5] != '-':
                    process_info_str = parts[5]
            else:
                # print(f"DEBUG_PY_PARSE: Unknown conn_type '{conn_type}' for line {line_num+1}", file=sys.stderr)
                continue

            if not local_addr_port or not peer_addr_port:
                # print(f"DEBUG_PY_PARSE: local_addr_port or peer_addr_port not set for line {line_num+1}: '{line}'", file=sys.stderr)
                continue

            # print(f"DEBUG_PY_PARSE: Line {line_num+1} Extracted L:'{local_addr_port}' P:'{peer_addr_port}'", file=sys.stderr)
            match_local = ip_port_regex.match(local_addr_port)
            match_peer = ip_port_regex.match(peer_addr_port)

            if not match_local or not match_peer:
                # This debug message can be very verbose if many non-localhost lines are present
                # print(f"DEBUG_PY_PARSE: Regex (IPv4 localhost) failed or not applicable for line {line_num+1}: '{line}'", file=sys.stderr)
                # print(f"DEBUG_PY_PARSE:   L_AddrPort: '{local_addr_port}', L_REPR: {repr(local_addr_port)}, Match_L: {match_local}", file=sys.stderr)
                # print(f"DEBUG_PY_PARSE:   P_AddrPort: '{peer_addr_port}', P_REPR: {repr(peer_addr_port)}, Match_P: {match_peer}", file=sys.stderr)
                continue
            
            local_ip = match_local.group(1)
            local_port_str = match_local.group(2)

            peer_ip = match_peer.group(1)
            peer_port_str = match_peer.group(2)

            # No need to check for '*' in port with this regex, as it only matches digits
            # if local_port_str == '*' or peer_port_str == '*':
            #     print(f"DEBUG_PY_PARSE: Skipping line {line_num+1} due to '*' port: '{line}'", file=sys.stderr)
            #     continue

            local_port = int(local_port_str)
            peer_port = int(peer_port_str)
            
            # IP normalization is not needed as we are matching a specific IP.

            parsed_connections.append({
                'local_full': local_addr_port,
                'peer_full': peer_addr_port,
                'local_ip': local_ip,
                'peer_ip': peer_ip,
                'local_port': local_port,
                'peer_port': peer_port,
                'process_info': process_info_str
            })
        except ValueError: # Handle int() conversion error for port
            # print(f"DEBUG_PY: ValueError parsing ports in line {line_num+1}: '{line}'")
            continue
        except IndexError: # Handle issues with parts list being too short
            # print(f"DEBUG_PY: IndexError parsing line {line_num+1}: '{line}'")
            continue
            
    return parsed_connections

def calculate_e2e_connections(connections):
    """
    Calculates the number of ephemeral-to-ephemeral connections.
    An e2e connection is defined as a connection where both its local and peer ports
    are unique among all the provided connections.
    It also flags connections where local_port == peer_port.
    """
    if not connections:
        return 0, []

    local_ports = [conn['local_port'] for conn in connections]
    peer_ports = [conn['peer_port'] for conn in connections]

    local_port_counts = Counter(local_ports)
    peer_port_counts = Counter(peer_ports)

    e2e_count = 0
    e2e_connections_list = []
    for conn in connections:
        if local_port_counts[conn['local_port']] == 1 and peer_port_counts[conn['peer_port']] == 1:
            # Create a deterministic label for the E2E connection based on actual LPORT and PPORT
            conn['e2e_label'] = f"E2E-{conn['local_port']}-{conn['peer_port']}"
            
            # The e2e_key for internal tracking of unique *communication channels* will still use sorted ports
            p1_sorted, p2_sorted = sorted((conn['local_port'], conn['peer_port']))
            conn['e2e_key'] = f"127.0.0.1:{p1_sorted}-127.0.0.1:{p2_sorted}" # for internal tracking

            e2e_count += 1
            # Check for port loop
            if conn['local_port'] == conn['peer_port']:
                conn['is_port_loop'] = True
            else:
                conn['is_port_loop'] = False # Ensure the key exists
            e2e_connections_list.append(conn)
    return e2e_count, e2e_connections_list

def analyze_current_connections(perform_detailed_analysis=True, trigger_info=None, potential_cot_log=None, perform_detailed_analysis_for_json=False, triggering_client_name=None):
    """
    Core logic for fetching, parsing, and analyzing connections.
    This is similar to the old main() but callable.
    If perform_detailed_analysis is True, it prints detailed E2E info and service connection info.
    If perform_detailed_analysis_for_json is True, it returns a list of dicts for JSON output (E2E only).
    Otherwise, it just returns the E2E count.
    Updates global ACTIVE_E2E_CONNECTIONS and ACTIVE_SERVICE_CONNECTIONS.
    Accepts trigger_info and potential_cot_log for contextual reporting.
    """
    global ACTIVE_E2E_CONNECTIONS # To modify it
    global ACTIVE_SERVICE_CONNECTIONS # To modify it

    current_time_seconds = int(time.time())
    current_time_iso = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(current_time_seconds))

    if perform_detailed_analysis_for_json:
        print(f"DEBUG_PY: Running DETAILED E2E connection analysis for JSON output at {time.strftime('%Y-%m-%d %H:%M:%S')}", file=sys.stderr)
    elif perform_detailed_analysis:
        print(f"DEBUG_PY: Running DETAILED connection analysis (E2E and Service) at {time.strftime('%Y-%m-%d %H:%M:%S')}", file=sys.stderr)
        if trigger_info:
            print(f"INFO: Detailed analysis trigger context: {trigger_info}", file=sys.stderr)
        if potential_cot_log:
            if COT_XML_PAYLOAD_REGEX.search(potential_cot_log):
                try:
                    parts = potential_cot_log.split("DEBUG - ", 1)
                    if len(parts) > 1:
                        print(f"INFO: Extracted Potential COT XML: {parts[1]}", file=sys.stderr)
                    else:
                        print(f"INFO: Associated Log Line (COT regex matched, but no 'DEBUG -'): {potential_cot_log}", file=sys.stderr)
                except Exception as e:
                    print(f"INFO: (Error trying to extract COT XML from log line: {e}) Log: {potential_cot_log}", file=sys.stderr)
            else:
                 print(f"INFO: Associated Log Line (Not full COT XML): {potential_cot_log}", file=sys.stderr)
    else:
        print(f"DEBUG_PY: Running E2E count analysis at {time.strftime('%Y-%m-%d %H:%M:%S')}", file=sys.stderr)

    raw_lines, conn_type = get_raw_connections()
    if not raw_lines:
        print("Error: Could not retrieve connection data.", file=sys.stderr)
        if perform_detailed_analysis: # Clear active connections if data is unavailable
            print("[EPHEMERAL-TO-EPHEMERAL LOCALHOST CONNECTIONS (Data Unavailable)]", file=sys.stderr)
            ACTIVE_E2E_CONNECTIONS.clear()
            print("[LOCALHOST CONNECTIONS TO KNOWN SERVICES (Data Unavailable)]", file=sys.stderr)
            ACTIVE_SERVICE_CONNECTIONS.clear()
        if perform_detailed_analysis_for_json:
            return []
        return 0

    all_parsed_connections = parse_connections(raw_lines, conn_type)
    localhost_connections = [c for c in all_parsed_connections if c['local_ip'] == '127.0.0.1' and c['peer_ip'] == '127.0.0.1']

    # --- E2E Connection Analysis --- 
    target_localhost_connections_for_e2e = []
    for c in localhost_connections:
        if not (c['local_port'] in KNOWN_PORTS_TO_EXCLUDE or c['peer_port'] in KNOWN_PORTS_TO_EXCLUDE):
            target_localhost_connections_for_e2e.append(c)
    
    e2e_count, e2e_list = calculate_e2e_connections(target_localhost_connections_for_e2e)

    if perform_detailed_analysis_for_json:
        json_output_list = []
        for conn in e2e_list:
            e2e_key_from_calc = conn['e2e_key']
            ss_details_str, proc_pid, proc_start_time, proc_name = inspect_e2e_connection_with_ss(conn['local_port'], conn['peer_port'])
            if e2e_key_from_calc not in ACTIVE_E2E_CONNECTIONS:
                ACTIVE_E2E_CONNECTIONS[e2e_key_from_calc] = {
                    'start_time': current_time_seconds, 
                    'netstat_info': conn.get('process_info', 'N/A'),
                    'first_seen_iso': current_time_iso
                }
            json_conn_details = {
                'label': conn['e2e_label'],
                'local_addr': f"{conn['local_ip']}:{conn['local_port']}",
                'peer_addr': f"{conn['peer_ip']}:{conn['peer_port']}",
                'pid': proc_pid if proc_pid != "N/A" else None,
                'process_name': proc_name if proc_name != "N/A" else None,
                'process_start_time': proc_start_time if proc_start_time not in ["N/A", "ErrorFetching"] else None,
                'ss_details': ss_details_str if not ss_details_str.startswith("SS_INFO:") else None,
                'is_localhost_both_sides': True
            }
            json_output_list.append(json_conn_details)
        
        seen_in_this_run_e2e_keys_json = {item['e2e_key'] for item in e2e_list}
        closed_keys_json = set(ACTIVE_E2E_CONNECTIONS.keys()) - seen_in_this_run_e2e_keys_json
        for key_closed in closed_keys_json:
            del ACTIVE_E2E_CONNECTIONS[key_closed]
        return json_output_list

    if not perform_detailed_analysis: # e2e_count_once mode
        return e2e_count

    # --- Detailed Console Output for E2E Connections ---
    print(f"\n[EPHEMERAL-TO-EPHEMERAL LOCALHOST CONNECTIONS ({e2e_count} found)]", file=sys.stderr)
    seen_in_this_run_e2e_keys = set()
    if e2e_list:
        for conn in e2e_list:
            e2e_key = conn['e2e_key']
            e2e_display_label = conn['e2e_label']
            seen_in_this_run_e2e_keys.add(e2e_key)
            display_conn = f"127.0.0.1:{conn['local_port']} -> 127.0.0.1:{conn['peer_port']}"
            port_loop_indicator = "[PORT_LOOP!] " if conn.get('is_port_loop') else ""

            if e2e_key not in ACTIVE_E2E_CONNECTIONS:
                ACTIVE_E2E_CONNECTIONS[e2e_key] = {'start_time': current_time_seconds, 'netstat_info': conn.get('process_info', 'N/A')}
                ss_details_str, proc_pid, proc_start_time, proc_name = inspect_e2e_connection_with_ss(conn['local_port'], conn['peer_port'])
                print("\n" + "="*70, file=sys.stderr)
                print(f"  NEW E2E DETECTED @ {time.strftime('%H:%M:%S', time.localtime(current_time_seconds))}", file=sys.stderr)
                
                # Check for recent PyTAK client connections for correlation
                correlated_pytak_clients = []
                for pytak_event in RECENTLY_CONNECTED_PYTAK_CLIENTS:
                    if (current_time_seconds - pytak_event['time']) <= PYTAK_EVENT_CORRELATION_WINDOW_SECONDS:
                        correlated_pytak_clients.append(f"{pytak_event['callsign']} (IP:{pytak_event['ip']} @ {time.strftime('%H:%M:%S', time.localtime(pytak_event['time']))})")
                
                if correlated_pytak_clients:
                    print(f"  Recent PyTAK   : { '; '.join(correlated_pytak_clients)}", file=sys.stderr)

                if triggering_client_name: print(f"  Context     : Possibly related to activity from '{triggering_client_name}'", file=sys.stderr)
                if trigger_info: print(f"  Trigger     : {trigger_info}", file=sys.stderr)
                print(f"  E2E_Label   : {e2e_display_label}", file=sys.stderr)
                print(f"  Connection  : {port_loop_indicator}{display_conn}", file=sys.stderr)
                if proc_pid != "N/A":
                    print(f"  SS PID      : {proc_pid}", file=sys.stderr)
                    if proc_name != "N/A": print(f"  SS Process  : {proc_name}", file=sys.stderr)
                    if proc_start_time != "N/A" and proc_start_time != "ErrorFetching": print(f"  Process Start : {proc_start_time}", file=sys.stderr)
                    elif proc_start_time == "ErrorFetching": print(f"  Process Start : (Error fetching start time)", file=sys.stderr)
                    else: print(f"  Process Start : (N/A from ps for PID {proc_pid})", file=sys.stderr)
                else: print(f"  SS PID      : (N/A from ss)", file=sys.stderr)
                if ss_details_str and not any(ss_details_str.startswith(prefix) for prefix in ["SS_INFO: No details found", "SS_INFO: Timeout inspecting", "SS_INFO: 'sudo', 'ss' or 'ps' command not found"]):
                    print(f"  SS Raw Out  :", file=sys.stderr); [print(f"    {line.strip()}", file=sys.stderr) for line in ss_details_str.splitlines()]
                elif ss_details_str: print(f"  SS Status   : {ss_details_str}", file=sys.stderr)
                print("="*70 + "\n", file=sys.stderr)
    else:
        print("--- No current E2E connections matching criteria ---", file=sys.stderr)
    
    closed_e2e_keys = set(ACTIVE_E2E_CONNECTIONS.keys()) - seen_in_this_run_e2e_keys
    for key in closed_e2e_keys:
        info = ACTIVE_E2E_CONNECTIONS[key]
        start_time = info['start_time']
        open_duration = current_time_seconds - start_time
        parts = key.split('-')
        display_key_approx = f"{parts[0]} <-> {parts[1]}" if len(parts) == 2 else key
        netstat_info = f" (Netstat Info: {info.get('netstat_info', 'N/A')})" if info.get('netstat_info', 'N/A') != 'N/A' else ""
        print(f"[CLOSED E2E] {display_key_approx}{netstat_info} was open for {open_duration}s (from {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time))})", file=sys.stderr)
        del ACTIVE_E2E_CONNECTIONS[key]

    # --- Detailed Console Output for Connections to Known Service Ports ---
    print(f"\n[LOCALHOST CONNECTIONS TO KNOWN SERVICES (Ports: {KNOWN_PORTS_TO_EXCLUDE}) ]", file=sys.stderr)
    seen_in_this_run_service_keys = set()
    found_service_connections_this_run = 0

    for conn in localhost_connections: # Iterate all 127.0.0.1 <-> 127.0.0.1 connections
        lport, pport = conn['local_port'], conn['peer_port']
        is_lport_service = lport in KNOWN_PORTS_TO_EXCLUDE
        is_pport_service = pport in KNOWN_PORTS_TO_EXCLUDE

        eph_port, svc_port, conn_from_eph_to_svc = None, None, False

        if is_lport_service and not is_pport_service: # Ephemeral (pport) connecting to Service (lport)
            svc_port, eph_port = lport, pport
            conn_from_eph_to_svc = True
        elif is_pport_service and not is_lport_service: # Ephemeral (lport) connecting to Service (pport)
            svc_port, eph_port = pport, lport
            conn_from_eph_to_svc = True
        
        if not conn_from_eph_to_svc: # Skip if not ephemeral to service (e.g. service-to-service, or already E2E handled)
            continue

        found_service_connections_this_run += 1
        # Key represents ephemeral port connecting TO service port
        service_conn_key = f"eph:{eph_port}-svc:{svc_port}"
        seen_in_this_run_service_keys.add(service_conn_key)
        display_conn = f"127.0.0.1:{eph_port} -> 127.0.0.1:{svc_port}"

        if service_conn_key not in ACTIVE_SERVICE_CONNECTIONS:
            ACTIVE_SERVICE_CONNECTIONS[service_conn_key] = {
                'start_time': current_time_seconds,
                'ephemeral_port': eph_port,
                'service_port': svc_port,
                'initial_netstat_info': conn.get('process_info', 'N/A') # From initial netstat parse
            }
            # For service connections, ss is called with (ephemeral_port, service_port)
            # to get info about the process owning the ephemeral port.
            ss_details_str, proc_pid, proc_start_time, proc_name = inspect_e2e_connection_with_ss(eph_port, svc_port)

            print("\n" + "-"*70, file=sys.stderr) # Use different separator for service conns
            print(f"  NEW SVC_CONN DETECTED @ {time.strftime('%H:%M:%S', time.localtime(current_time_seconds))}", file=sys.stderr)
            if triggering_client_name: print(f"  Client Context: Possibly related to '{triggering_client_name}'", file=sys.stderr)
            if trigger_info: print(f"  Trigger       : {trigger_info}", file=sys.stderr)
            print(f"  Connection    : {display_conn}", file=sys.stderr)
            
            if proc_pid != "N/A":
                print(f"  Owner PID     : {proc_pid} (process on ephemeral port {eph_port})", file=sys.stderr)
                if proc_name != "N/A": print(f"  Owner Process : {proc_name}", file=sys.stderr)
                if proc_start_time != "N/A" and proc_start_time != "ErrorFetching": print(f"  Process Start : {proc_start_time}", file=sys.stderr)
                elif proc_start_time == "ErrorFetching": print(f"  Process Start : (Error fetching start time for PID {proc_pid})", file=sys.stderr)
                else: print(f"  Process Start : (N/A from ps for PID {proc_pid})", file=sys.stderr)
            else: print(f"  Owner PID     : (N/A from ss for ephemeral port {eph_port})", file=sys.stderr)

            if ss_details_str and not any(ss_details_str.startswith(prefix) for prefix in ["SS_INFO: No details found", "SS_INFO: Timeout inspecting", "SS_INFO: 'sudo', 'ss' or 'ps' command not found"]):
                print(f"  SS Raw Out    :", file=sys.stderr); [print(f"    {line.strip()}", file=sys.stderr) for line in ss_details_str.splitlines()]
            elif ss_details_str: print(f"  SS Status     : {ss_details_str}", file=sys.stderr)
            print("-"*70 + "\n", file=sys.stderr)
    
    if found_service_connections_this_run == 0:
        print("--- No new or active connections from ephemeral ports to known services found this cycle ---", file=sys.stderr)

    closed_service_keys = set(ACTIVE_SERVICE_CONNECTIONS.keys()) - seen_in_this_run_service_keys
    for key_closed in closed_service_keys:
        info = ACTIVE_SERVICE_CONNECTIONS[key_closed]
        start_time = info['start_time']
        eph_port = info['ephemeral_port']
        svc_port = info['service_port']
        open_duration = current_time_seconds - start_time
        display_closed_conn = f"127.0.0.1:{eph_port} -> 127.0.0.1:{svc_port}"
        # initial_info = f" (Initial Netstat: {info.get('initial_netstat_info', 'N/A')})" if info.get('initial_netstat_info', 'N/A') != 'N/A' else ""
        print(f"[CLOSED SVC_CONN] {display_closed_conn} was open for {open_duration}s (from {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time))})", file=sys.stderr)
        del ACTIVE_SERVICE_CONNECTIONS[key_closed]
    print("--- End of Connections to Known Services Analysis ---", file=sys.stderr)

    # Fallback Return Logic - primarily for e2e_count_once or if detailed_list_once needs a count.
    # detailed_list_once performs prints to stderr directly.
    return e2e_count # For detailed_list_once, this count is informational; for e2e_count_once, it's the primary output.

def monitor_log_and_analyze(log_file_path, detailed_delay):
    """
    Main function to tail the log, detect events, and trigger connection analysis.
    """
    # Local state for this monitoring session
    last_emit_timestamp = 0
    detailed_check_queued = False
    # These store the context for the *next* detailed check when it's triggered
    last_triggering_event_info = "Initial script startup" 
    last_potential_cot_message = None
    last_triggering_client_for_context = None # New variable for specific client context

    print(f"INFO: Starting OTS connection monitor. Log: {log_file_path}")
    print(f"INFO: Detailed check delay after emit/activity: {detailed_delay}s")

    initial_connections_result = subprocess.run(['netstat', '-tna'], capture_output=True, text=True, check=False)
    if initial_connections_result.stdout:
        established_count = initial_connections_result.stdout.count("ESTABLISHED")
        print(f"Initial ESTABLISHED connections (raw netstat): {established_count}")

    print("\n--- Performing initial detailed E2E connection analysis ---")
    analyze_current_connections(perform_detailed_analysis=True, 
                                trigger_info=last_triggering_event_info,
                                potential_cot_log=last_potential_cot_message,
                                triggering_client_name=last_triggering_client_for_context)
    last_triggering_event_info = None # Reset after use
    last_potential_cot_message = None # Reset after use
    last_triggering_client_for_context = None # Reset after use
    print("--- Initial analysis complete ---\n")

    tail_process = None
    try:
        tail_process = subprocess.Popen(
            ['tail', '-F', '-n0', log_file_path],
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True,
            bufsize=1,  # Line buffered
            universal_newlines=True # Ensures text mode
        )
        print(f"INFO: tail process started (PID: {tail_process.pid}) for {log_file_path}", file=sys.stderr)

        poller = select.poll()
        poller.register(tail_process.stdout, select.POLLIN)

        while True:
            current_time = time.time()

            # Check for new log lines (non-blocking) and process all available
            lines_processed_this_cycle = 0
            while poller.poll(0): # Loop as long as there's data from tail
                log_line = tail_process.stdout.readline()
                if log_line:
                    lines_processed_this_cycle += 1
                    log_line = log_line.strip()
                    script_timestamp_ms = f"{int(current_time)}.{int((current_time - int(current_time)) * 1000):03d}"
                    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(current_time)))}.{int((current_time - int(current_time)) * 1000):03d} SCRIPT_SEES_LOG] {log_line}", file=sys.stdout)
                    
                    current_line_is_significant = False
                    # Tentative trigger/COT for THIS line, to decide if globals are updated
                    current_line_trigger_candidate = None
                    current_line_cot_candidate = None
                    current_line_client_name_candidate = None # For specific client context
                    current_line_rabbitmq_event_detected = False # New flag

                    # 0. Prune old PyTAK client connection events first
                    RECENTLY_CONNECTED_PYTAK_CLIENTS[:] = [
                        event for event in RECENTLY_CONNECTED_PYTAK_CLIENTS
                        if (current_time - event['time']) < PYTAK_EVENT_CORRELATION_WINDOW_SECONDS
                    ]

                    # PYTAK_DIAG_ANALYZER: Log the line being checked for PYTAK_CLIENT_CONNECT_EVENT
                    print(f"PYTAK_DIAG_ANALYZER: Checking line for PYTAK_CLIENT_CONNECT_EVENT: {log_line}")

                    # 1. Check for our specific PYTAK_CLIENT_CONNECT_EVENT
                    pytak_match = PYTAK_CLIENT_CONNECT_REGEX.search(log_line)
                    if pytak_match:
                        uid, callsign, ip = pytak_match.groups()
                        event_time = current_time # Use script's current time as event time
                        RECENTLY_CONNECTED_PYTAK_CLIENTS.append({
                            'uid': uid,
                            'callsign': callsign,
                            'ip': ip,
                            'time': event_time
                        })
                        # This event is significant and should queue a detailed check
                        current_line_is_significant = True
                        current_line_trigger_candidate = f"PyTAK Client Connect: {callsign} (UID:{uid}) from IP:{ip}"
                        last_triggering_client_for_context = f"PyTAK-{callsign}" # Use a distinct naming for context
                        print(f"INFO: [{time.strftime('%H:%M:%S')}] Detected PYTAK_CLIENT_CONNECT_EVENT for {callsign}. Stored for correlation.", file=sys.stderr)

                    # 1. Check for specific client patterns (renumbered to 2)
                    for client_name, pattern in INTERESTING_CLIENT_PATTERNS.items():
                        if pattern.search(log_line):
                            current_line_trigger_candidate = f"Client '{client_name}' activity detected."
                            current_line_client_name_candidate = client_name # Capture client name
                            current_line_is_significant = True
                            if COT_XML_PAYLOAD_REGEX.search(log_line):
                                current_line_cot_candidate = log_line
                            # If client activity but not COT, current_line_cot_candidate remains None
                            break 
                    
                    # 2. Check for RabbitMQ consumer creation (NEW)
                    if RABBITMQ_CONSUMER_REGEX.search(log_line):
                        current_line_rabbitmq_event_detected = True
                        current_line_is_significant = True
                        # If no client trigger was set yet by specific client patterns, set a RabbitMQ specific one.
                        if not current_line_trigger_candidate:
                            # Attempt to make the trigger info more specific if possible, e.g. by extracting queue name.
                            # For now, a generic message. User can enhance regex and extraction.
                            match = RABBITMQ_CONSUMER_REGEX.search(log_line)
                            extracted_detail = f" ('{match.group(0)}')" if match else ""
                            current_line_trigger_candidate = f"RabbitMQ consumer activity detected{extracted_detail}."
                        # If current_line_client_name_candidate was already set by a client pattern, it remains.
                        # This allows linking RabbitMQ activity to a specific client if the log line contains both.

                    # 3. If no specific client or RabbitMQ trigger, check if it's a COT payload on its own
                    if not current_line_trigger_candidate and COT_XML_PAYLOAD_REGEX.search(log_line):
                        current_line_trigger_candidate = "COT XML payload detected in log."
                        current_line_cot_candidate = log_line
                        current_line_is_significant = True
                        
                    # Check for general OTS emit
                    if OTS_EMIT_REGEX.search(log_line):
                        if not current_line_trigger_candidate: 
                            current_line_trigger_candidate = "General OTS Emit detected."
                        current_line_is_significant = True
                        # If emit line is also COT, current_line_cot_candidate would have been set above.
                        # If emit line is NOT COT, current_line_cot_candidate remains as it was (or None).

                    if current_line_is_significant:
                        last_emit_timestamp = current_time 
                        detailed_check_queued = True
                        
                        # Update global context for the pending check
                        # Priority for trigger_info: Specific Client > COT Payload > General Emit
                        if current_line_trigger_candidate:
                            last_triggering_event_info = current_line_trigger_candidate
                        if current_line_client_name_candidate: # Store specific client
                            last_triggering_client_for_context = current_line_client_name_candidate
                        
                        # Revised Logic for last_potential_cot_message:
                        # If the current significant line IS a COT payload, it becomes the (new) potential COT.
                        # If the current significant line is NOT a COT payload, the existing last_potential_cot_message (if any)
                        # is preserved, as it might be relevant to the event sequence leading to this trigger.
                        if COT_XML_PAYLOAD_REGEX.search(log_line): # Current line is a COT XML payload
                            last_potential_cot_message = log_line
                        # Else (current line is significant but NOT a COT payload, e.g., client connect, general emit without full COT):
                        # last_potential_cot_message remains as it was from a previous COT-bearing line.
                        # It will only be cleared after the detailed analysis uses it.

                        print(f"INFO: [{time.strftime('%H:%M:%S')}] Significant event ('{last_triggering_event_info}'). Detailed check queued.", file=sys.stderr)
                        # More detailed debug for what specifically was detected on this line
                        debug_event_components = []
                        if current_line_client_name_candidate:
                            debug_event_components.append(f"Client='{current_line_client_name_candidate}'")
                        if current_line_rabbitmq_event_detected:
                            debug_event_components.append("RabbitMQ_Event")
                        if current_line_cot_candidate: # This means COT_XML_PAYLOAD_REGEX matched *this* line
                            debug_event_components.append("COT_Payload")
                        if OTS_EMIT_REGEX.search(log_line) and not current_line_cot_candidate and not current_line_client_name_candidate and not current_line_rabbitmq_event_detected:
                            debug_event_components.append("General_OTS_Emit")
                        
                        print(f"DEBUG_MONITOR: Event components on this line: {', '.join(debug_event_components) if debug_event_components else 'None_Specific'}", file=sys.stderr)
                        print(f"DEBUG_MONITOR:   Queued with Trigger Context: '{last_triggering_event_info}'", file=sys.stderr)
                        print(f"DEBUG_MONITOR:   Client for Context: '{last_triggering_client_for_context}'", file=sys.stderr)
                        if last_potential_cot_message:
                             print(f"DEBUG_MONITOR:   Potential COT Log (if any) starts with: {last_potential_cot_message[:120]}", file=sys.stderr)
                        print(f"DEBUG_MONITOR:   Log line that set/updated queue trigger: {log_line[:120]}", file=sys.stderr)

                elif tail_process.poll() is not None: # Tail process died
                    print("ERROR: Tail process died. Exiting monitor loop.", file=sys.stderr)
                    # Ensure cleanup happens if we exit from here
                    if tail_process and tail_process.poll() is None: # Double check before terminate
                        print(f"INFO: Terminating tail process (PID: {tail_process.pid}) due to error in monitor loop.", file=sys.stderr)
                        tail_process.terminate()
                        try:
                            tail_process.wait(timeout=1)
                        except subprocess.TimeoutExpired:
                            tail_process.kill()
                    return # Exit the main monitoring function
                else:
                    # readline() returned empty but process alive and poller said data (unlikely for stdout)
                    break # Break from inner while poller.poll(0) loop (the one processing all available lines)
            
            # Optional debug for burst processing - enable if needed
            # if lines_processed_this_cycle > 0:
            #     print(f"DEBUG_PY: Processed {lines_processed_this_cycle} log lines in this script cycle.", file=sys.stderr)

            # --- Timer checks --- 
            if detailed_check_queued and (current_time - last_emit_timestamp) >= detailed_delay:
                print(f"\nINFO: [{time.strftime('%H:%M:%S', time.localtime(current_time))}] OTS Emit/Activity Quiescence ({detailed_delay}s). Triggering DETAILED connection analysis...", file=sys.stderr)
                
                print(f"DEBUG_BEFORE_ANALYSIS: Trigger: '{last_triggering_event_info}'. Potential COT Log that will be passed: {'SET' if last_potential_cot_message else 'None'}", file=sys.stderr)
                if last_potential_cot_message:
                    print(f"DEBUG_BEFORE_ANALYSIS:   Actual COT Log content: {last_potential_cot_message[:150]}", file=sys.stderr)

                print(f"DEBUG_MONITOR: Analyzing with Trigger: '{last_triggering_event_info}'. Potential COT Log: {'SET' if last_potential_cot_message else 'None'}", file=sys.stderr)
                if last_potential_cot_message:
                    print(f"DEBUG_MONITOR:   Passing Potential COT Log starting with: {last_potential_cot_message[:120]}", file=sys.stderr) # Increased preview

                analyze_current_connections(perform_detailed_analysis=True, 
                                            trigger_info=last_triggering_event_info, 
                                            potential_cot_log=last_potential_cot_message,
                                            triggering_client_name=last_triggering_client_for_context)
                print("--- Detailed analysis after emit/activity complete ---\n", file=sys.stderr)
                detailed_check_queued = False
                last_triggering_event_info = None # Reset after use
                last_potential_cot_message = None # Reset after use
                last_triggering_client_for_context = None # Reset after use

            time.sleep(1) # Main loop polling interval (for timer checks and for checking for next batch of logs)

    except FileNotFoundError:
        print(f"ERROR: 'tail' command not found. Please ensure it's installed.", file=sys.stderr)
    except KeyboardInterrupt:
        print("INFO: KeyboardInterrupt received. Shutting down...", file=sys.stderr)
    except Exception as e:
        print(f"ERROR: Exception in monitor_log_and_analyze: {e}", file=sys.stderr)
    finally:
        if tail_process and tail_process.poll() is None:
            print(f"INFO: Terminating tail process (PID: {tail_process.pid}) on exit.", file=sys.stderr)
            tail_process.terminate()
            try:
                tail_process.wait(timeout=2) # Wait for a bit
                print(f"INFO: Tail process (PID: {tail_process.pid}) terminated gracefully.", file=sys.stderr)
            except subprocess.TimeoutExpired:
                print(f"WARNING: Tail process (PID: {tail_process.pid}) did not terminate gracefully, killing.", file=sys.stderr)
                tail_process.kill()
        print("INFO: Monitor loop finished. Cleaning up.", file=sys.stderr)

def main_cli():
    parser = argparse.ArgumentParser(description="Monitor OpenTAKServer logs and analyze TCP connections for ephemeral port exhaustion.")
    parser.add_argument('--log-file', type=str, default=DEFAULT_LOG_FILE,
                        help=f"Path to the OpenTAKServer log file to monitor. Default: {DEFAULT_LOG_FILE}")
    parser.add_argument('--detailed-delay', type=int, default=DEFAULT_DETAILED_CHECK_DELAY_SECONDS,
                        help=f"Delay in seconds after last OTS emit to perform a detailed connection analysis. Default: {DEFAULT_DETAILED_CHECK_DELAY_SECONDS}s")
    parser.add_argument('--known-ports-file', type=str, default=DEFAULT_KNOWN_PORTS_FILE,
                        help=f"Path to the INI file for known service ports. Default: {DEFAULT_KNOWN_PORTS_FILE}")
    
    # Keep old modes for now, or decide if they are still needed
    # For instance, a one-shot analysis mode might still be useful for testing.
    parser.add_argument('--mode', choices=['monitor', 'detailed_list_once', 'e2e_count_once', 'json_e2e_details_once'], default='monitor',
                        help="Operation mode: 'monitor' for continuous log monitoring (default), "
                             "'detailed_list_once' for a single detailed analysis run, "
                             "'e2e_count_once' for a single E2E count, "
                             "'json_e2e_details_once' for a single E2E list in JSON format.")

    args = parser.parse_args()

    global KNOWN_PORTS_TO_EXCLUDE
    KNOWN_PORTS_TO_EXCLUDE = load_known_ports(args.known_ports_file)

    # Basic signal handling for graceful shutdown
    def signal_handler(signum, frame):
        print(f"INFO: Signal {signal.Signals(signum).name} received. Exiting gracefully...", file=sys.stderr)
        # The main loop's finally block should also trigger.
        # If tail_log_file uses a subprocess, ensure it's cleaned up.
        # This might involve finding the Popen object and terminating it if it's still alive.
        # For now, sys.exit() will trigger finally blocks.
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    if args.mode == 'monitor':
        monitor_log_and_analyze(args.log_file, args.detailed_delay)
    elif args.mode == 'detailed_list_once':
        print("--- Performing one-shot detailed E2E connection analysis ---", file=sys.stderr)
        analyze_current_connections(perform_detailed_analysis=True)
        print("--- One-shot analysis complete ---", file=sys.stderr)
    elif args.mode == 'e2e_count_once':
        # Output the count directly to stdout for shell script compatibility
        count = analyze_current_connections(perform_detailed_analysis=False)
        print(count) # Raw count to stdout
        # Also print descriptive info to stderr for direct runs
        print("--- Performing one-shot E2E connection count ---", file=sys.stderr)
        print(f"Total ephemeral-to-ephemeral localhost connections: {count}", file=sys.stderr)
        print("--- One-shot count complete ---", file=sys.stderr)
    elif args.mode == 'json_e2e_details_once':
        # In this mode, analyze_current_connections should return a list of dicts
        # and we print it as JSON to stdout. Errors/logs still to stderr.
        e2e_details_list = analyze_current_connections(perform_detailed_analysis=False, perform_detailed_analysis_for_json=True)
        if e2e_details_list is not None:
            print(json.dumps(e2e_details_list, indent=2))
        else:
            # Should not happen if perform_detailed_analysis_for_json is handled correctly
            print(json.dumps([])) # Output empty JSON array if something went wrong

if __name__ == "__main__":
    # Ensure debug prints go to stderr if not specified otherwise
    # sys.stdout = sys.stderr # Uncomment this if you want ALL prints to go to stderr by default

    # Call the new main CLI entry point
    main_cli() 