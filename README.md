# Spyware 2.0 - System Monitoring Server

A simple TCP server for remote system monitoring through /proc filesystem.
It can work without root privileges!
## Features
- CPU information monitoring
- Memory usage statistics
- Remote command execution

## Usage
```bash
#Compiling programs
gcc server.c -o server
gcc client.c -o client
# Start server
./server

# Connect client
./client
