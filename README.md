# End-to-End Encrypted Messenger
Final Project for CS 4900/5900 : Cryptography and Secure Communication

This project is a secure chat application that implements true End-to-End Encryption (E2EE) and Digital Signatures. The central server acts only as a relay and cannot read or tamper with any of the messages sent between users.

## How it Works
1. **Confidentiality:** Messages are symmetrically encrypted using lightning-fast **AES-GCM (128-bit)**.
2. **Key Exchange:** The AES session key is securely wrapped using the recipient's **RSA Public Key (with OAEP padding)**.
3. **Authenticity & Integrity:** The entire packet is digitally signed using the sender's **RSA Private Key (with PSS padding)** before transit. If a Man-in-the-Middle (or the server) tampers with the message, the signature validation will fail and the client will actively reject the packet.

## Requirements
* Python 3
* `cryptography` library

To install the required library, run:
```bash
pip install cryptography
```

## How to Run

We have provided a convenient launcher script that will start the server and both clients (Alice and Bob) simultaneously.

Simply open **one terminal** and run:
```bash
python run_all.py
```

* The Server will start in the background.
* Alice's GUI window will open.
* Bob's GUI window will open.

When you are finished testing, simply press `Ctrl+C` in your terminal to cleanly shut down the server and both clients at the same time!