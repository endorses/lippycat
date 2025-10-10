#!/bin/bash
# Generate synthetic network traffic for testing lippycat
# This script creates various types of network traffic to test
# protocol detection, packet processing, and filter distribution

set -euo pipefail

echo "🚀 Starting synthetic traffic generation..."

# Function to generate HTTP traffic
generate_http_traffic() {
    echo "📡 Generating HTTP traffic..."
    for i in {1..10}; do
        curl -s -o /dev/null http://processor.test.local:8080/ || true
        sleep 0.1
    done
}

# Function to generate DNS traffic
generate_dns_traffic() {
    echo "📡 Generating DNS traffic..."
    for i in {1..10}; do
        nslookup google.com 8.8.8.8 > /dev/null 2>&1 || true
        sleep 0.1
    done
}

# Function to generate TCP SYN scans (looks like VoIP signaling)
generate_tcp_traffic() {
    echo "📡 Generating TCP traffic..."
    # SIP port
    nc -zv -w1 processor.test.local 5060 2>&1 || true
    # HTTP port
    nc -zv -w1 processor.test.local 80 2>&1 || true
    # HTTPS port
    nc -zv -w1 processor.test.local 443 2>&1 || true
}

# Function to replay PCAP files if available
replay_pcap_files() {
    echo "📡 Replaying PCAP files..."
    if [ -d "/testdata/pcaps" ]; then
        for pcap in /testdata/pcaps/*.pcap; do
            if [ -f "$pcap" ]; then
                echo "  Replaying: $(basename $pcap)"
                tcpreplay --intf1=eth0 --mbps=1 "$pcap" 2>&1 || true
            fi
        done
    else
        echo "  No PCAP files found in /testdata/pcaps/"
    fi
}

# Function to generate mixed traffic
generate_mixed_traffic() {
    echo "📡 Generating mixed protocol traffic..."

    # Continuous traffic generation
    while true; do
        generate_http_traffic &
        generate_dns_traffic &
        generate_tcp_traffic &

        # Generate VoIP traffic if Python script is available
        if [ -f "/scripts/generate_voip_traffic.py" ]; then
            python3 /scripts/generate_voip_traffic.py &
        fi

        wait
        sleep 5
    done
}

# Main execution
case "${1:-mixed}" in
    http)
        generate_http_traffic
        ;;
    dns)
        generate_dns_traffic
        ;;
    tcp)
        generate_tcp_traffic
        ;;
    pcap)
        replay_pcap_files
        ;;
    mixed)
        generate_mixed_traffic
        ;;
    *)
        echo "Usage: $0 {http|dns|tcp|pcap|mixed}"
        echo "  http  - Generate HTTP traffic"
        echo "  dns   - Generate DNS queries"
        echo "  tcp   - Generate TCP connection attempts"
        echo "  pcap  - Replay PCAP files from /testdata/pcaps/"
        echo "  mixed - Generate all types of traffic (default)"
        exit 1
        ;;
esac
