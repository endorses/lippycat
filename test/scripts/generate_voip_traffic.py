#!/usr/bin/env python3
"""
Generate synthetic VoIP traffic (SIP and RTP) for testing lippycat
Uses scapy to craft realistic SIP INVITE messages and RTP packets
"""

import time
import random
from scapy.all import IP, UDP, Raw, send, RandString

def generate_sip_invite(src_ip="172.30.0.100", dst_ip="172.30.0.10",
                       from_user="alice", to_user="bob"):
    """Generate a SIP INVITE message"""

    call_id = f"{random.randint(1000000, 9999999)}@{src_ip}"
    branch = f"z9hG4bK{random.randint(100000, 999999)}"
    tag = f"tag-{random.randint(10000, 99999)}"

    sip_invite = f"""INVITE sip:{to_user}@{dst_ip} SIP/2.0
Via: SIP/2.0/UDP {src_ip}:5060;branch={branch}
From: "{from_user}" <sip:{from_user}@{src_ip}>;tag={tag}
To: "{to_user}" <sip:{to_user}@{dst_ip}>
Call-ID: {call_id}
CSeq: 1 INVITE
Contact: <sip:{from_user}@{src_ip}:5060>
Content-Type: application/sdp
Content-Length: 200
Max-Forwards: 70
User-Agent: lippycat-test-generator/1.0

v=0
o={from_user} 123456 654321 IN IP4 {src_ip}
s=Test Call
c=IN IP4 {src_ip}
t=0 0
m=audio 10000 RTP/AVP 0 8
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
"""

    packet = IP(src=src_ip, dst=dst_ip)/UDP(sport=5060, dport=5060)/Raw(load=sip_invite)
    return packet

def generate_rtp_packet(src_ip="172.30.0.100", dst_ip="172.30.0.10",
                       src_port=10000, dst_port=20000, seq=0):
    """Generate an RTP packet"""

    # RTP header (simplified)
    # V=2, P=0, X=0, CC=0, M=0, PT=0 (PCMU), Sequence, Timestamp, SSRC
    rtp_version = 0x80  # V=2
    rtp_payload_type = 0  # PCMU
    rtp_header = bytes([
        rtp_version,
        rtp_payload_type,
        (seq >> 8) & 0xFF,
        seq & 0xFF,
        0, 0, 0, 0,  # Timestamp (simplified)
        0, 0, 0, 1,  # SSRC (simplified)
    ])

    # Add dummy audio payload (160 bytes for 20ms of PCMU audio)
    payload = bytes([0] * 160)

    packet = IP(src=src_ip, dst=dst_ip)/UDP(sport=src_port, dport=dst_port)/Raw(load=rtp_header + payload)
    return packet

def generate_voip_call_session():
    """Generate a complete VoIP call session"""

    src_ip = f"172.30.0.{random.randint(100, 199)}"
    dst_ip = "172.30.0.10"  # Processor

    users = [
        ("alice", "bob"),
        ("charlie", "dave"),
        ("eve", "frank"),
        ("grace", "henry"),
    ]
    from_user, to_user = random.choice(users)

    print(f"📞 Generating VoIP call: {from_user} → {to_user}")

    # Send SIP INVITE
    print("  Sending SIP INVITE...")
    invite = generate_sip_invite(src_ip, dst_ip, from_user, to_user)
    send(invite, verbose=0)

    # Simulate RTP stream (10 packets = 200ms of audio)
    print("  Sending RTP stream...")
    src_port = random.randint(10000, 20000)
    dst_port = random.randint(20000, 30000)

    for seq in range(10):
        rtp = generate_rtp_packet(src_ip, dst_ip, src_port, dst_port, seq)
        send(rtp, verbose=0)
        time.sleep(0.02)  # 20ms per packet

    print("  ✓ VoIP call session complete")

def main():
    """Main function - generate continuous VoIP traffic"""

    print("📡 Starting VoIP traffic generation...")
    print("   Press Ctrl+C to stop")

    try:
        while True:
            generate_voip_call_session()
            time.sleep(2)  # Wait between calls
    except KeyboardInterrupt:
        print("\n✓ VoIP traffic generation stopped")

if __name__ == "__main__":
    main()
