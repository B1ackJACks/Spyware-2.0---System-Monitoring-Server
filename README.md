# Spyware 2.0 - System Monitoring Server

A simple TLS-secured server that allows remote monitoring of system information via the /proc filesystem.
All communication is encrypted using TLS 1.3.It can work without root privileges!
## DISCLEIMER!!!!
This project is for educational and demonstration purposes only!!!
It intentionally disables certificate verification on the client side and exposes system data without authentication.
Do NOT use in real environments without proper hardening.
## Features
- CPU information monitoring
- Memory usage statistics
- Remote command execution
- Encryption of the transmission channel

## Usage
```bash
#Before running the server, you must generate a server certificate and private key in the same directory as the executable:
openssl req -x509 -newkey rsa:4096 -keyout server-key.pem -out server-cert.pem -days 365 -nodes -subj "/CN=localhost"

#Compiling programs
gcc server.c -o server
gcc client.c -o client
# Start server
./server

# Connect client
./client
