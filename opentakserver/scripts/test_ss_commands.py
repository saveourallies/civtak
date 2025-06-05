#!/usr/bin/env python3
import subprocess
import sys

def run_command(command_args):
    print(f"--- Testing command: {' '.join(command_args)} ---", file=sys.stderr)
    try:
        process = subprocess.run(
            command_args,
            capture_output=True,
            text=True,
            check=False  # Don't raise exception on non-zero exit
        )
        print(f"Return Code: {process.returncode}", file=sys.stderr)
        print("--- STDOUT ---", file=sys.stderr)
        if process.stdout:
            print(process.stdout)
        else:
            print("(empty)", file=sys.stderr)
        print("--- STDERR ---", file=sys.stderr)
        if process.stderr:
            print(process.stderr, file=sys.stderr)
        else:
            print("(empty)", file=sys.stderr)
        
        # For direct analysis, also print stdout to actual stdout
        if process.stdout and process.returncode == 0:
             print(f"\n--- Raw STDOUT for {' '.join(command_args)} (if successful) ---")
             print(process.stdout)
             print(f"--- End Raw STDOUT for {' '.join(command_args)} ---\n")


    except FileNotFoundError:
        print(f"Error: Command '{command_args[0]}' not found.", file=sys.stderr)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
    print("------\n", file=sys.stderr)

if __name__ == "__main__":
    print("Starting ss command tests...\n", file=sys.stderr)
    
    # Test 'ss -ntHp'
    # -n: numeric (don't resolve names)
    # -t: tcp
    # -H: No header line
    # -p: Show process using socket
    run_command(["ss", "-ntHp"])
    
    # Test 'ss -ntH'
    # -n: numeric
    # -t: tcp
    # -H: No header line
    run_command(["ss", "-ntH"])
    
    # For comparison, let's also run the netstat command we know works
    # -t: tcp
    # -n: numeric
    # -a: all sockets (listening and non-listening)
    # run_command(["netstat", "-tna"]) # We know this one works, so maybe not necessary here.

    print("ss command tests finished.", file=sys.stderr) 