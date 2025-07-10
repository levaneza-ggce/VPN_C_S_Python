# Python VPN Client-Server System

A simple VPN (Virtual Private Network) client-server system implemented in Python. This project provides a secure tunnel for network traffic between a client and server using SSL/TLS encryption.

## Features

- Secure communication using SSL/TLS encryption
- Client and server components
- Cross-platform support (Linux, macOS, Windows)
- Interactive client mode
- Self-signed certificate generation for testing
- Network utilities for managing tunnels and routes
- Packet manipulation utilities
- Encryption/decryption utilities

## System Requirements

- Python 3.6 or higher
- Root/Administrator privileges (required for network interface manipulation)
- Python packages:
  - `cryptography` (for encryption/decryption)
- Linux-specific requirements (for full VPN functionality):
  - `ip` command
  - `ifconfig` command
  - `route` command

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/vpn-client-server.git
   cd vpn-client-server
   ```

2. Install required Python packages:
   ```
   pip install cryptography
   ```

## Usage

### Running the Server

To start the VPN server with default settings:

```
sudo python main.py server --generate-cert
```

This will:
- Generate a self-signed SSL certificate (if it doesn't exist)
- Start the server on all interfaces (0.0.0.0) on port 5000

Additional server options:
```
python main.py server --help
```

### Running the Client

To connect to a VPN server:

```
sudo python main.py client --host <server_ip>
```

For interactive mode (allows sending commands to the server):
```
sudo python main.py client --host <server_ip> --interactive
```

Additional client options:
```
python main.py client --help
```

### System Information

To check if your system meets the requirements:

```
python main.py --system-info
```

## How It Works

### VPN Server

The server component:
1. Creates a TCP socket and listens for client connections
2. Uses SSL/TLS to secure the connection
3. Authenticates clients
4. Creates a secure tunnel for traffic forwarding
5. Routes traffic between clients and the internet

### VPN Client

The client component:
1. Connects to the VPN server using TCP
2. Establishes a secure SSL/TLS connection
3. Authenticates with the server
4. Creates a virtual network interface (TUN/TAP) on Linux
5. Routes specified traffic through the VPN tunnel

### Network Tunneling

On Linux systems, the VPN uses TUN/TAP interfaces to create a virtual network device. This allows the system to:
1. Capture outgoing packets from applications
2. Encrypt and send them through the secure tunnel to the server
3. Receive encrypted packets from the server
4. Decrypt and inject them into the local network stack

## Project Structure

- `main.py` - Main entry point for the application
- `server.py` - VPN server implementation
- `client.py` - VPN client implementation
- `utils.py` - Shared utilities and helper functions

## Security Considerations

This VPN implementation is primarily for educational purposes. For production use, consider the following:

1. Use proper certificate management (not self-signed certificates)
2. Implement stronger authentication mechanisms
3. Add traffic validation and filtering
4. Implement perfect forward secrecy
5. Add protection against replay attacks
6. Consider using established VPN protocols like OpenVPN or WireGuard

## Troubleshooting

### Common Issues

1. **Permission Denied**: VPN functionality requires root/administrator privileges. Run with `sudo` on Linux/macOS or as Administrator on Windows.

2. **Certificate Errors**: If you see SSL/TLS errors, ensure the certificate is properly generated and accessible.

3. **Missing Dependencies**: Run `python main.py --system-info` to check for missing dependencies.

4. **TUN/TAP Interface Issues**: On Linux, ensure the TUN/TAP module is loaded:
   ```
   sudo modprobe tun
   ```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- This project is for educational purposes to demonstrate network programming concepts
- Inspired by various open-source VPN implementations