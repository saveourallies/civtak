#!/bin/bash

# Output file for tcpdump capture
OUTPUT_DIR=~/ots/logs
OUTPUT_FILE="$OUTPUT_DIR/cot_traffic_$(date +%Y%m%d_%H%M%S).pcap"
OUTPUT_TXT="$OUTPUT_DIR/cot_traffic_$(date +%Y%m%d_%H%M%S).txt"

# Create the output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Function to show usage
usage() {
    echo "Usage: $0 [-p port] [-i interface] [-t seconds]"
    echo "  -p : Port to monitor (default: 8089)"
    echo "  -i : Network interface (default: any)"
    echo "  -t : Duration in seconds (default: continuous)"
    exit 1
}

# Default values
PORT=8089
INTERFACE="any"
DURATION=""

# Parse command line arguments
while getopts "p:i:t:" opt; do
    case $opt in
        p)
            PORT=$OPTARG
            ;;
        i)
            INTERFACE=$OPTARG
            ;;
        t)
            DURATION="-G ${OPTARG} -W 1"
            ;;
        *)
            usage
            ;;
    esac
done

echo "==================================================================="
echo "OpenTAK COT Traffic Monitor"
echo "==================================================================="
echo "Capturing COT traffic on port $PORT"
echo "Interface: $INTERFACE"
if [ -n "$DURATION" ]; then
    echo "Duration: $OPTARG seconds"
else
    echo "Duration: Continuous (press Ctrl+C to stop)"
fi
echo "Packets saved to: $OUTPUT_FILE"
echo "Human-readable output: $OUTPUT_TXT"
echo "==================================================================="

# Build the tcpdump command
# Capture both binary and human-readable output
TCPDUMP_CMD="sudo tcpdump -i $INTERFACE -s 0 -nn $DURATION -w $OUTPUT_FILE port $PORT"
TCPDUMP_TXT="sudo tcpdump -i $INTERFACE -s 0 -nn -A port $PORT"

# Run tcpdump for binary capture
echo "Running packet capture: $TCPDUMP_CMD"
$TCPDUMP_CMD &
TCPDUMP_PID=$!

# Run tcpdump for text output
echo "Running text capture: $TCPDUMP_TXT > $OUTPUT_TXT"
$TCPDUMP_TXT | tee "$OUTPUT_TXT" | grep -A 3 -B 3 "event" | grep -A 2 -B 2 "callsign" &
TCPDUMP_TXT_PID=$!

# Handle graceful shutdown
trap 'echo "Stopping capture..."; kill $TCPDUMP_PID $TCPDUMP_TXT_PID 2>/dev/null; exit' INT TERM

# Wait for the commands to finish
wait $TCPDUMP_PID
wait $TCPDUMP_TXT_PID

echo "Capture complete!"
echo "Binary packet data saved to: $OUTPUT_FILE"
echo "Human-readable output saved to: $OUTPUT_TXT"

