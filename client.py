import socket
import ssl
import threading
import logging
import argparse
import sys
import time
from typing import Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('vpn_client')

class VPNClient:
    def __init__(self, server_host: str, server_port: int, ca_cert: Optional[str] = None):
        """
        Initialize the VPN client.

        Args:
            server_host: The VPN server hostname or IP address
            server_port: The VPN server port
            ca_cert: Path to the CA certificate file for server verification (optional)
        """
        self.server_host = server_host
        self.server_port = server_port
        self.ca_cert = ca_cert
        self.client_socket = None
        self.running = False
        self.receive_thread = None

    def connect(self) -> bool:
        """
        Connect to the VPN server.

        Returns:
            bool: True if connection was successful, False otherwise
        """
        try:
            # Create a TCP socket
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Create SSL context
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

            # If CA certificate is provided, use it for server verification
            if self.ca_cert:
                context.load_verify_locations(self.ca_cert)
            else:
                # In testing environments, we might want to disable certificate verification
                # WARNING: This is insecure and should not be used in production
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                logger.warning("SSL certificate verification is disabled. Connection is not secure!")

            # Connect to the server
            logger.info("Connecting to VPN server at {}:{}...".format(self.server_host, self.server_port))
            self.client_socket.connect((self.server_host, self.server_port))

            # Wrap the socket with SSL
            self.client_socket = context.wrap_socket(self.client_socket, server_hostname=self.server_host)

            # Check if the connection was successful
            if self.client_socket:
                logger.info("Connected to VPN server successfully")
                self.running = True

                # Start a thread to receive data from the server
                self.receive_thread = threading.Thread(target=self.receive_data)
                self.receive_thread.daemon = True
                self.receive_thread.start()

                return True

            return False

        except ssl.SSLError as e:
            logger.error("SSL Error: {}".format(e))
            return False
        except socket.error as e:
            logger.error("Socket Error: {}".format(e))
            return False
        except Exception as e:
            logger.error("Connection Error: {}".format(e))
            return False

    def receive_data(self) -> None:
        """Receive and process data from the VPN server."""
        try:
            while self.running:
                data = self.client_socket.recv(4096)
                if not data:
                    logger.info("Server closed the connection")
                    self.disconnect()
                    break

                # Process the received data
                logger.info("Received from server: {}".format(data.decode('utf-8', errors='ignore')))

                # Here you would implement the actual VPN tunneling logic
                # For a real VPN, you would handle the tunneled packets

        except ssl.SSLError as e:
            logger.error("SSL Error while receiving data: {}".format(e))
            self.disconnect()
        except socket.error as e:
            logger.error("Socket Error while receiving data: {}".format(e))
            self.disconnect()
        except Exception as e:
            logger.error("Error while receiving data: {}".format(e))
            self.disconnect()

    def send_data(self, data: bytes) -> bool:
        """
        Send data to the VPN server.

        Args:
            data: The data to send

        Returns:
            bool: True if data was sent successfully, False otherwise
        """
        if not self.running or not self.client_socket:
            logger.error("Cannot send data: Not connected to server")
            return False

        try:
            self.client_socket.send(data)
            return True
        except Exception as e:
            logger.error("Error sending data: {}".format(e))
            self.disconnect()
            return False

    def disconnect(self) -> None:
        """Disconnect from the VPN server."""
        self.running = False

        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
            self.client_socket = None

        logger.info("Disconnected from VPN server")

    def start_tunnel(self) -> None:
        """
        Start the VPN tunnel.

        In a real VPN client, this would set up the virtual network interface
        and route traffic through the VPN tunnel.
        """
        if not self.running:
            logger.error("Cannot start tunnel: Not connected to server")
            return

        logger.info("Starting VPN tunnel...")

        # In a real implementation, this would:
        # 1. Set up a virtual network interface (TUN/TAP)
        # 2. Configure routing to direct traffic through the VPN
        # 3. Handle packet capture and forwarding

        # For this simple example, we'll just send a message to the server
        self.send_data(b"START_TUNNEL")

        logger.info("VPN tunnel started")

    def stop_tunnel(self) -> None:
        """Stop the VPN tunnel."""
        if not self.running:
            return

        logger.info("Stopping VPN tunnel...")

        # Send a message to the server to stop the tunnel
        try:
            self.send_data(b"STOP_TUNNEL")
        except:
            pass

        # Disconnect from the server
        self.disconnect()

        logger.info("VPN tunnel stopped")

def interactive_mode(client: VPNClient) -> None:
    """
    Run the client in interactive mode, allowing the user to send commands.

    Args:
        client: The VPN client instance
    """
    print("\nVPN Client Interactive Mode")
    print("---------------------------")
    print("Commands:")
    print("  send <message> - Send a message to the server")
    print("  tunnel - Start the VPN tunnel")
    print("  quit - Disconnect and exit")

    while client.running:
        try:
            command = input("\nEnter command: ").strip()

            if command.lower() == "quit":
                client.stop_tunnel()
                break
            elif command.lower() == "tunnel":
                client.start_tunnel()
            elif command.lower().startswith("send "):
                message = command[5:]  # Remove "send " prefix
                client.send_data(message.encode('utf-8'))
                print("Sent: {}".format(message))
            else:
                print("Unknown command. Type 'quit' to exit.")

        except KeyboardInterrupt:
            print("\nInterrupted by user")
            client.stop_tunnel()
            break
        except Exception as e:
            print("Error: {}".format(e))

def main() -> None:
    """Main function to run the VPN client."""
    parser = argparse.ArgumentParser(description='VPN Client')
    parser.add_argument('--host', default='localhost', help='VPN server hostname or IP address')
    parser.add_argument('--port', type=int, default=5000, help='VPN server port')
    parser.add_argument('--ca-cert', help='Path to the CA certificate file for server verification')
    parser.add_argument('--interactive', action='store_true', help='Run in interactive mode')

    args = parser.parse_args()

    # Create the VPN client
    client = VPNClient(args.host, args.port, args.ca_cert)

    # Connect to the server
    if not client.connect():
        logger.error("Failed to connect to VPN server")
        sys.exit(1)

    try:
        if args.interactive:
            # Run in interactive mode
            interactive_mode(client)
        else:
            # Run in automatic mode
            client.start_tunnel()

            # Keep the client running
            print("VPN client is running. Press Ctrl+C to stop.")
            while client.running:
                time.sleep(1)

    except KeyboardInterrupt:
        print("\nVPN client stopped by user")
    finally:
        client.stop_tunnel()

if __name__ == "__main__":
    main()
