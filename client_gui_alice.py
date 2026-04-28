

import sys
import json
import uuid
import socket
import queue
import threading
import tkinter as tk
from tkinter import ttk, messagebox

from crypto_logic import (
    ensure_user_keys,
    load_public_pem,
    create_encrypted_packet,
    decrypt_packet_for_user,
)

HOST = "127.0.0.1"
PORT = 50600


def send_json(sock, obj):
    payload = json.dumps(obj).encode("utf-8")
    prefix = f"{len(payload):08d}".encode("utf-8")
    sock.sendall(prefix + payload)


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Socket closed")
        data += chunk
    return data


def recv_json(sock):
    prefix = recv_exact(sock, 8)
    size = int(prefix.decode("utf-8"))
    payload = recv_exact(sock, size)
    return json.loads(payload.decode("utf-8"))


class MessengerGUI:
    def __init__(self, username):
        self.username = username
        self.sock = None
        self.receiver_started = False
        self.pending = {}
        self.pending_lock = threading.Lock()

        self.root = tk.Tk()
        self.root.title(f"E2EE Messenger - {username}")
        self.root.geometry("760x560")

        self.status_var = tk.StringVar(value="Not connected")
        self.tamper_var = tk.BooleanVar(value=False)

        self.build_ui()

    def build_ui(self):
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text=f"Logged in as: {self.username}", font=("Arial", 12, "bold")).pack(side="left")
        self.connect_btn = ttk.Button(top, text="Connect", command=self.connect_to_server)
        self.connect_btn.pack(side="right", padx=5)
        self.refresh_btn = ttk.Button(top, text="Refresh Users", command=self.refresh_users, state="disabled")
        self.refresh_btn.pack(side="right", padx=5)

        middle = ttk.Frame(self.root, padding=10)
        middle.pack(fill="both", expand=True)

        left = ttk.LabelFrame(middle, text="Online Users", padding=10)
        left.pack(side="left", fill="y", padx=(0, 10))

        self.user_list = tk.Listbox(left, height=18, width=25)
        self.user_list.pack(fill="y")
        ttk.Label(left, text="Select a recipient from this list").pack(pady=(8, 0))

        right = ttk.LabelFrame(middle, text="Messages", padding=10)
        right.pack(side="left", fill="both", expand=True)

        self.chat_box = tk.Text(right, height=22, state="disabled", wrap="word")
        self.chat_box.pack(fill="both", expand=True)

        bottom = ttk.Frame(self.root, padding=10)
        bottom.pack(fill="x")

        ttk.Label(bottom, text="Recipient:").grid(row=0, column=0, sticky="w")
        self.recipient_entry = ttk.Entry(bottom, width=25)
        self.recipient_entry.grid(row=0, column=1, padx=5, sticky="we")

        ttk.Button(bottom, text="Use Selected User", command=self.use_selected_user).grid(row=0, column=2, padx=5)

        ttk.Label(bottom, text="Message:").grid(row=1, column=0, sticky="nw", pady=(8, 0))
        self.message_text = tk.Text(bottom, height=5, width=50)
        self.message_text.grid(row=1, column=1, columnspan=2, padx=5, pady=(8, 0), sticky="we")

        ttk.Checkbutton(
            bottom,
            text="Tamper packet on server (for testing)",
            variable=self.tamper_var
        ).grid(row=2, column=1, sticky="w", pady=(8, 0))

        ttk.Button(bottom, text="Send Secure Message", command=self.send_message).grid(row=2, column=2, padx=5,
                                                                                       pady=(8, 0), sticky="e")

        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief="sunken", anchor="w")
        status_bar.pack(fill="x", side="bottom")

        bottom.columnconfigure(1, weight=1)
        self.user_list.bind("<<ListboxSelect>>", lambda event: self.use_selected_user())

    def append_chat(self, text):
        self.chat_box.configure(state="normal")
        self.chat_box.insert("end", text + "\n")
        self.chat_box.see("end")
        self.chat_box.configure(state="disabled")

    def use_selected_user(self):
        selection = self.user_list.curselection()
        if selection:
            chosen = self.user_list.get(selection[0])
            self.recipient_entry.delete(0, "end")
            self.recipient_entry.insert(0, chosen)

    def _register_pending(self):
        request_id = str(uuid.uuid4())
        q = queue.Queue(maxsize=1)
        with self.pending_lock:
            self.pending[request_id] = q
        return request_id, q

    def _resolve_pending(self, request_id, msg):
        with self.pending_lock:
            q = self.pending.pop(request_id, None)
        if q is not None:
            q.put(msg)
            return True
        return False

    def request_reply(self, payload, timeout=5.0):
        if not self.sock:
            raise RuntimeError("Not connected")

        request_id, q = self._register_pending()
        payload = dict(payload)
        payload["request_id"] = request_id
        send_json(self.sock, payload)

        try:
            return q.get(timeout=timeout)
        except queue.Empty:
            with self.pending_lock:
                self.pending.pop(request_id, None)
            raise TimeoutError("Timed out waiting for server reply")

    def connect_to_server(self):
        try:
            ensure_user_keys(self.username)
            public_pem = load_public_pem(self.username)

            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((HOST, PORT))

            if not self.receiver_started:
                threading.Thread(target=self.receive_loop, daemon=True).start()
                self.receiver_started = True

            reply = self.request_reply({
                "action": "register",
                "username": self.username,
                "public_key": public_pem.decode("utf-8"),
            })

            if reply.get("status") != "ok":
                raise RuntimeError(reply.get("message", "Registration failed"))

            self.status_var.set(f"Connected to {HOST}:{PORT}")
            self.append_chat(f"[SYSTEM] Connected and registered as {self.username}")
            self.connect_btn.config(state="disabled")
            self.refresh_btn.config(state="normal")
            self.refresh_users()

        except Exception as e:
            messagebox.showerror("Connection Error", str(e))

    def refresh_users(self):
        try:
            reply = self.request_reply({"action": "list_users"})
            if reply.get("status") == "ok":
                self.user_list.delete(0, "end")
                for user in reply["users"]:
                    if user != self.username:
                        self.user_list.insert("end", user)
                self.append_chat("[SYSTEM] User list refreshed")
            else:
                self.append_chat(f"[ERROR] Refresh failed: {reply}")
        except Exception as e:
            self.append_chat(f"[ERROR] Could not refresh users: {e}")

    def get_public_key(self, target):
        reply = self.request_reply({"action": "get_public_key", "target": target})
        if reply.get("status") != "ok":
            raise RuntimeError(reply.get("message", "Failed to get public key"))
        return reply["public_key"].encode("utf-8")

    def send_message(self):
        target = self.recipient_entry.get().strip()
        text = self.message_text.get("1.0", "end").strip()

        if not self.sock:
            messagebox.showwarning("Not Connected", "Connect to server first.")
            return
        if not target:
            messagebox.showwarning("Missing Recipient", "Choose or enter a recipient.")
            return
        if not text:
            messagebox.showwarning("Missing Message", "Type a message first.")
            return

        try:
            public_key_pem = self.get_public_key(target)
            packet = create_encrypted_packet(self.username, public_key_pem, text)

            action = "tamper_relay" if self.tamper_var.get() else "relay"
            reply = self.request_reply({
                "action": action,
                "target": target,
                "packet": packet,
            })

            if reply.get("status") != "ok":
                raise RuntimeError(reply.get("message", "Send failed"))

            mode = "TAMPER TEST" if self.tamper_var.get() else "NORMAL"
            self.append_chat(f"[YOU -> {target}] ({mode}) {text}")
            self.message_text.delete("1.0", "end")

        except Exception as e:
            messagebox.showerror("Send Error", str(e))

    def receive_loop(self):
        try:
            while True:
                msg = recv_json(self.sock)

                request_id = msg.get("request_id")
                if request_id is not None:
                    self._resolve_pending(request_id, msg)
                    continue

                if msg.get("action") == "deliver":
                    packet = msg["packet"]
                    sender = packet.get("from", "unknown")
                    try:
                        plaintext = decrypt_packet_for_user(self.username, packet)
                        self.root.after(0, lambda s=sender, p=plaintext: self.append_chat(f"[{s} -> YOU] {p}"))
                    except Exception as e:
                        self.root.after(0, lambda s=sender, err=str(e): self.append_chat(
                            f"[SECURITY] Message from {s} failed to decrypt or was tampered with. ({err})"
                        ))
                    continue

                self.root.after(0, lambda m=msg: self.append_chat(f"[SERVER] {m}"))

        except Exception as e:
            self.root.after(0, lambda err=str(e): self.append_chat(f"[ERROR] Receiver stopped: {err}"))

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    username = "alice"  # change here for each user
    print(f"Starting client as: {username}")
    app = MessengerGUI(username)
    app.run()



