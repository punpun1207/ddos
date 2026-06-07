#!/bin/bash
# run_ddos_defense.sh - Start Ryu + Mininet DDoS demo

RYU_APP="1cl_strict_1.py"
MININET_SCRIPT="generate_ddos_trafic1.py"
RYU_LOG="ryu.log"
MN_LOG="mininet.log"

# Kill any existing Ryu and Mininet
sudo pkill -f ryu-manager
sudo mn -c 2>/dev/null

echo "Starting Ryu controller (logging to $RYU_LOG)..."
ryu-manager $RYU_APP --verbose > $RYU_LOG 2>&1 &
RYU_PID=$!
sleep 3

echo "Starting Mininet DDoS attack..."
sudo python3 $MININET_SCRIPT > $MN_LOG 2>&1 &
MN_PID=$!

# Function to cleanup
cleanup() {
    echo -e "\nStopping processes..."
    sudo kill $RYU_PID $MN_PID 2>/dev/null
    sudo mn -c
    exit 0
}
trap cleanup SIGINT SIGTERM

# Wait for both processes
wait $RYU_PID $MN_PID