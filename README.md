# MQTT Attack and Defense — ECE6612 Project

This project demonstrates a security analysis of the MQTT protocol, including both offensive and defensive techniques. Specifically, we implement:

- **MQTT sniffing and spoofing attacks**
- **Cryptographic defense using  digital signatures**

## Overview

MQTT is a lightweight publish-subscribe protocol widely used in IoT environments. However, due to its minimal default security, it is vulnerable to various network-layer attacks such as **packet sniffing, replay, and message injection**.

This project simulates these vulnerabilities and implements a **digital signature-based defense mechanism** to ensure message integrity and authenticity.


## Attack Module

We demonstrate the following:

- **Sniffing**: Capture legitimate MQTT `PUBLISH` packets using tools like `pyshark` or `tcpdump`.
- **Spoofing**: Inject malicious MQTT messages that appear to come from a legitimate client.
- **Replay**: Resend previously captured packets to test if the broker or subscriber accepts duplicate/fake data.

*Example:*
- Legitimate client sends: `Temperature = 75`
- Attacker injects: `Temperature = 67`
- Subscriber sees both — the attack succeeds.


## Defense Module

To defend against such attacks, we introduce:

### Digital Signatures

- Each message is signed with the sender’s **private RSA key**.
- The receiver verifies the message using the sender’s **public key**.
- Signature covers the payload and a **timestamp**, preventing tampering and replay.

*Effect:*  
Even if an attacker captures a packet, they **cannot generate a valid signature** for a forged message — the spoofed data is rejected.

