import subprocess
import time
import sys

def main():
    print("Starting Server...")
    # Use sys.executable to ensure we use the same python environment (.venv)
    server = subprocess.Popen([sys.executable, "server.py"])
    time.sleep(1) # Give server a second to start

    print("Starting Alice...")
    alice = subprocess.Popen([sys.executable, "client_gui_alice.py"])

    print("Starting Bob...")
    bob = subprocess.Popen([sys.executable, "client_gui_bob.py"])

    print("\nAll applications started! Press Ctrl+C in this terminal to close everything.")

    try:
        # Keep script running while GUIs are open
        server.wait()
        alice.wait()
        bob.wait()
    except KeyboardInterrupt:
        print("\nShutting down all applications...")
        server.terminate()
        alice.terminate()
        bob.terminate()
        print("Done!")

if __name__ == "__main__":
    main()