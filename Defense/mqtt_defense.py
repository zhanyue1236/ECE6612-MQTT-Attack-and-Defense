import json, time, base64
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import paho.mqtt.client as mqtt

# Load private key
key = RSA.import_key(open("device_private.pem").read())

def sign_message(msg: str, ts: int) -> str:
    # Optional: increase temperature by 1 degree
    # msg = msg.split("=")[0] + "=" + str(int(msg.split("=")[1]) + 1)
    payload = msg + str(ts)
    h = SHA256.new(payload.encode())
    signature = pkcs1_15.new(key).sign(h)
    return base64.b64encode(signature).decode()

def publish():
    client = mqtt.Client()
    # Connect with username and password
    client.username_pw_set("hck", "hckhck")
    res = client.connect("ec2-44-202-154-174.compute-1.amazonaws.com", 1888, 60)
    if res != 0:
        print("Failed to connect to MQTT broker")
        print("Error code:", res)
        return
    # Send a message every 5 seconds
    while True:
        msg = "temperature = 411"
        ts = int(time.time())
        sig = sign_message(msg, ts)
        # Optional: modify the message to simulate drift
        # msg = msg.split("=")[0] + "= " + str(int(msg.split("=")[1]) + 1)
        payload = {
            "msg": msg,
            "ts": ts,
            "sig": sig
        }
        print(payload)
        client.publish("wsdz", json.dumps(payload))
        print("[Device] Published:", payload)
        time.sleep(5)

publish()