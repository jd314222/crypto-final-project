

import json
import socket
import threading

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


class RelayServer:
    def __init__(self):
        self.users = {}
        self.lock = threading.Lock()

    def reply(self, sock, request_id, body):
        out = dict(body)
        if request_id is not None:
            out["request_id"] = request_id
        send_json(sock, out)

    def handle_client(self, sock):
        username = None
        try:
            while True:
                msg = recv_json(sock)
                action = msg.get("action")
                request_id = msg.get("request_id")

                if action == "register":
                    username = msg["username"]
                    public_key = msg["public_key"]
                    with self.lock:
                        self.users[username] = {"public_key": public_key, "socket": sock}
                    print(f"[SERVER] Registered {username}")
                    self.reply(sock, request_id, {"status": "ok", "message": f"{username} registered"})

                elif action == "list_users":
                    with self.lock:
                        names = sorted(self.users.keys())
                    self.reply(sock, request_id, {"status": "ok", "users": names})

                elif action == "get_public_key":
                    target = msg["target"]
                    with self.lock:
                        target_user = self.users.get(target)
                    if target_user is None:
                        self.reply(sock, request_id, {"status": "error", "message": "User not found"})
                    else:
                        self.reply(sock, request_id, {
                            "status": "ok",
                            "target": target,
                            "public_key": target_user["public_key"],
                        })

                elif action == "relay":
                    target = msg["target"]
                    packet = msg["packet"]
                    with self.lock:
                        target_user = self.users.get(target)

                    if target_user is None:
                        self.reply(sock, request_id, {"status": "error", "message": "Target not online"})
                    else:
                        print(f"[SERVER] Relaying packet from {packet.get('from')} to {target}")
                        print(f"[SERVER] Packet preview: {str(packet)[:180]}")
                        send_json(target_user["socket"], {"action": "deliver", "packet": packet})
                        self.reply(sock, request_id, {"status": "ok", "message": f"Delivered to {target}"})

                elif action == "tamper_relay":
                    target = msg["target"]
                    packet = msg["packet"]
                    with self.lock:
                        target_user = self.users.get(target)

                    if target_user is None:
                        self.reply(sock, request_id, {"status": "error", "message": "Target not online"})
                    else:
                        tampered = dict(packet)
                        if "encrypted_message" in tampered and tampered["encrypted_message"]:
                            s = tampered["encrypted_message"]
                            tampered["encrypted_message"] = ("A" if s[0] != "A" else "B") + s[1:]
                        elif "encrypted_session_key" in tampered and tampered["encrypted_session_key"]:
                            s = tampered["encrypted_session_key"]
                            tampered["encrypted_session_key"] = ("A" if s[0] != "A" else "B") + s[1:]
                        print(f"[SERVER] Tampering with packet from {packet.get('from')} to {target}")
                        send_json(target_user["socket"], {"action": "deliver", "packet": tampered})
                        self.reply(sock, request_id, {"status": "ok", "message": f"Tampered packet delivered to {target}"})

                else:
                    self.reply(sock, request_id, {"status": "error", "message": "Unknown action"})

        except Exception as e:
            print(f"[SERVER] Client disconnected: {e}")
        finally:
            if username:
                with self.lock:
                    current = self.users.get(username)
                    if current and current["socket"] is sock:
                        del self.users[username]
                        print(f"[SERVER] Removed {username}")
            try:
                sock.close()
            except Exception:
                pass

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((HOST, PORT))
            server.listen()
            print(f"[SERVER] Listening on {HOST}:{PORT}")
            while True:
                sock, addr = server.accept()
                print(f"[SERVER] Connection from {addr}")
                threading.Thread(target=self.handle_client, args=(sock,), daemon=True).start()


if __name__ == "__main__":
    RelayServer().start()
