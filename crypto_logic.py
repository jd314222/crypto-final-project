"""
crypto_logic.py

Final Project: CS 4900/5900 : Cryptography and Secure Communication
Stedent Starter File
"""

import os
import base64
from pathlib import Path

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


DATA_DIR = Path("e2ee_data")


def ensure_data_dir():
    DATA_DIR.mkdir(exist_ok=True)


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8"))


def generate_rsa_keypair():
    # TODO 1:
    # Generate an RSA-2048 private key.
    # public_exponent=65537, key_size=2048
    # 
    # Then serialize:
    #   - private key to PEM (A format used to store that key) using private_bytes(...)
    #   - public key to PEM using public_bytes(...)
    # Hints: See encryption_builder() here: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/
    #
    # Return:
    #   private_pem, public_pem

    # Generating the private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # serializing to PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    
    public_key = private_key.public_key()
    
    # Serializing public_key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem


def save_keys(username: str, private_pem: bytes, public_pem: bytes):
    ensure_data_dir()
    (DATA_DIR / f"{username}_private.pem").write_bytes(private_pem)
    (DATA_DIR / f"{username}_public.pem").write_bytes(public_pem)


def load_private_key(username: str):
    # TODO 2:
    # Read the private key PEM file and return the loaded private key object.
    # hints: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/
    #
    # htins: https://docs.python.org/3/library/pathlib.html#pathlib.Path.read_bytes
    ensure_data_dir()
    pem_data = (DATA_DIR / f"{username}_private.pem").read_bytes()
    
    # Loading the private key from the pem_data as shown in docs
    private_key = serialization.load_pem_private_key(pem_data, password=None)
    return private_key


def load_public_pem(username: str) -> bytes:
    ensure_data_dir()
    return (DATA_DIR / f"{username}_public.pem").read_bytes()


def load_public_key_from_pem(public_pem: bytes):
    # TODO 3:
    # Convert PEM bytes into a public key object.
    #
    # hints: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/

    public_key = serialization.load_pem_public_key(public_pem)
    return public_key


def rsa_encrypt(public_key, plaintext: bytes) -> bytes:
    # TODO 4:
    # Encrypt plaintext using RSA-OAEP with SHA-256.
    #
    # Hint: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
    #   
    #

    # Following exact same encryption process as in docs using OAEP
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    # TODO 5:
    # Decrypt ciphertext using RSA-OAEP with SHA-256.
    #
    # Hint: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
    #   

    # Following exact same decryption process as in docs using OAEP
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


def aes_encrypt(session_key: bytes, plaintext: bytes):
    # TODO 6:
    # Encrypt plaintext using AES-GCM.
    #
    # hint: https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM
    aesgcm = AESGCM(session_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad=None)
    return nonce, ciphertext


def aes_decrypt(session_key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    # TODO 7:
    # Decrypt ciphertext using AES-GCM.
    #
    # hint: https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM
    aesgcm = AESGCM(session_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad=None)
    return plaintext


def ensure_user_keys(username: str):
    ensure_data_dir()
    priv_path = DATA_DIR / f"{username}_private.pem"
    pub_path = DATA_DIR / f"{username}_public.pem"

    if not priv_path.exists() or not pub_path.exists():
        try:
            private_pem, public_pem = generate_rsa_keypair()
            save_keys(username, private_pem, public_pem)
        except NotImplementedError:
            # Keeps the GUI running before TODO 1 is implemented.
            if not priv_path.exists():
                priv_path.write_bytes(b"")
            if not pub_path.exists():
                pub_path.write_bytes(b"")


def create_encrypted_packet(sender: str, recipient_public_key_pem: bytes, message_text: str) -> dict:
    # TODO 8:
    # Create the encrypted packet using hybrid encryption.
    #
    # Steps:
    #   1. Generate a random session key that will be used to encrypt this message.
    #   2. Load the recipient’s public key so only they can decrypt the message.
    #   3. Encrypt the message using AES-GCM with the session key.
    #   4. Encrypt the session key using the recipient’s RSA public key.
    #   5. Put everything together (sender, nonce, encrypted message, encrypted session key) into a packet and send it.
    #
    # Return format:
    #   {
    #       "type": "encrypted_message",
    #       "from": sender,
    #       "nonce": b64e(nonce),
    #       "encrypted_session_key": b64e(encrypted_session_key),
    #       "encrypted_message": b64e(encrypted_message),
    #   }
    #
    # Very Important:
    # Do not change the field names.
    return {
        "type": "encrypted_message",
        "from": sender,
        "nonce": "",
        "encrypted_session_key": "",
        "encrypted_message": "",
        "student_note": "TODO 8 not implemented: create_encrypted_packet()",
    }


def decrypt_packet_for_user(username: str, packet: dict) -> str:
    # Temporary placeholder behavior:
    # If TODO 8 was not implemented, the packet will include student_note.
    note = packet.get("student_note")
    if note:
        return f"[NOT IMPLEMENTED YET] {note}"

    # TODO 9:
    # Decrypt the delivered packet.
    #
    # Steps:
    #   1.Load your private key so you can decrypt data intended for you.
    #   2.Decode the nonce from the packet (convert from base64 to bytes).
    #   3.Decode the encrypted session key from the packet.
    #   4.Decode the encrypted message from the packet.
    #   5.Use your private key to decrypt the session key.
    #   6.Use the session key and nonce to decrypt the message using AES-GCM.
    #   7.Convert the decrypted message into readable text and return it.
    raise NotImplementedError("TODO 9 not implemented: decrypt_packet_for_user()")