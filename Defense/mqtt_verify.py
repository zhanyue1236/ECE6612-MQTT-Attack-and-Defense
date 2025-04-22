import json, base64
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import paho.mqtt.client as mqtt

# Load public key
pubkey = RSA.import_key(open("device_public.pem").read())

def verify_signature(msg: str, ts: int, sig_b64: str) -> bool:
    try:
        payload = msg + str(ts)
        h = SHA256.new(payload.encode())
        sig = base64.b64decode(sig_b64)
        pkcs1_15.new(pubkey).verify(h, sig)
        return True
    except (ValueError, TypeError):
        return False

def on_message(client, userdata, msg):
    try:
        data = json.loads(msg.payload.decode())
        valid = verify_signature(data["temp"], data["ts"], data["sig"])
        print(f"[Client] Received: {data['temp']}, Valid: {valid}")
    except Exception as e:
        print("[Client] Error processing message:", e)

def subscribe():
    client = mqtt.Client()
    
    # Set username and password
    client.username_pw_set(username="hck", password="hckhck")

    # Register message callback
    client.on_message = on_message

    # Connect to remote MQTT broker
    client.connect("ec2-3-84-26-116.compute-1.amazonaws.com", 1888, 60)

    # Subscribe to topic
    client.subscribe("ece6612")

    # Start listening loop
    client.loop_forever()

if __name__ == "__main__":
    subscribe()