import json, time, base64
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import paho.mqtt.client as mqtt

#Load private key
key = RSA.import_key(open("device_private.pem").read())

def sign_message(msg: str, ts: int) -> str:
    # make the temperature 1 degree more
    # msg = msg.split("=")[0] + "=" + str(int(msg.split("=")[1]) + 1)
    payload = msg + str(ts)
    h = SHA256.new(payload.encode())
    signature = pkcs1_15.new(key).sign(h)
    return base64.b64encode(signature).decode()

def publish():
    client = mqtt.Client()
    # connect with username and password
    client.username_pw_set("hck", "hckhck")
    res = client.connect("ec2-44-202-154-174.compute-1.amazonaws.com", 1888, 60)
    if res != 0:
        print("Failed to connect to MQTT broker")
        print("Error code:", res)
        return
    # send message every 5 seconds
    while True:
        msg = "temperature = 411"
        ts = int(time.time())
        sig = sign_message(msg, ts)
        # make mgs q degree more
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

'''
import json, base64
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import paho.mqtt.client as mqtt

#Load public key
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
        valid = verify_signature(data["msg"], data["ts"], data["sig"])
        print(f"[Client] Received: {data['msg']}, Valid: {valid}")
    except Exception as e:
        print("[Client] Error processing message:", e)

def subscribe():
    client = mqtt.Client()
    client.on_message = on_message
    client.connect("localhost", 1883, 60)
    client.subscribe("iot/device1/data")
    client.loop_forever()

if __name__ == "main":
    subscribe()
'''