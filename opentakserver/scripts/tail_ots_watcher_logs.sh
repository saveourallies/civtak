#!/bin/bash
# Simple script to tail the logs for the ots_log_watcher.service

echo "Tailing logs for ots_log_watcher.service... (Press Ctrl+C to stop)"
sudo journalctl -f -u ots_log_watcher.service --no-pager 