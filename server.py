import socket
import ssl
import threading
import os
import logging
import argparse
from typing import Tuple, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('vpn_server')

class VPNServer:
    def __init__(self, host: str, port: int, cert_file: str, key_file: str):
        """
        Initialize the VPN server.
        
        Args:
            host: The host address to bind the server to
            port: The port to listen on
            cert_file: Path to the SSL certificate file
            key_file: Path to the SSL key file
        """
        self.host = host
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file
        self.clients = {}
        self.running = False
        self.server_socket = None
        
    def start(self) -> None:
        """Start the VPN server and listen for client connections."""
        # Create a TCP socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            # Bind the socket to the specified host and port
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            logger.info(f"VPN Server started on {self.host}:{self.port}")
            
            # Create SSL context
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
            
            # Accept client connections
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    logger.info(f"New connection from {client_address}")
                    
                    # Wrap the socket with SSL
                    ssl_socket = context.wrap_socket(client_socket, server_side=True)
                    
                    # Start a new thread to handle the client
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(ssl_socket, client_address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except ssl.SSLError as e:
                    logger.error(f"SSL Error: {e}")
                except Exception as e:
                    logger.error(f"Error accepting connection: {e}")
                    if not self.running:
                        break
        
        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            self.stop()
    
    def handle_client(self, client_socket: ssl.SSLSocket, client_address: Tuple[str, int]) -> None:
        """
        Handle a client connection.
        
        Args:
            client_socket: The SSL socket connected to the client
            client_address: The client's address (host, port)
        """
        client_id = f"{client_address[0]}:{client_address[1]}"
        self.clients[client_id] = client_socket
        
        try:
            # Authentication would go here
            logger.info(f"Client {client_id} authenticated successfully")
            
            # Send welcome message
            client_socket.send(b"Welcome to the VPN server. You are now connected securely.")
            
            # Main client handling loop
            while self.running:
                data = client_socket.recv(4096)
                if not data:
                    logger.info(f"Client {client_id} disconnected")
                    break
                
                # Process the received data
                logger.debug(f"Received data from {client_id}: {data[:100]}...")
                
                # Here you would implement the actual VPN tunneling logic
                # For a real VPN, you would forward packets between the client and the internet
                
                # Echo back for this simple example
                client_socket.send(b"Received: " + data)
                
        except Exception as e:
            logger.error(f"Error handling client {client_id}: {e}")
        finally:
            # Clean up
            if client_id in self.clients:
                del self.clients[client_id]
            try:
                client_socket.close()
            except:
                pass
            logger.info(f"Connection with {client_id} closed")
    
    def stop(self) -> None:
        """Stop the VPN server and close all connections."""
        self.running = False
        
        # Close all client connections
        for client_id, client_socket in self.clients.items():
            try:
                client_socket.close()
            except:
                pass
        self.clients.clear()
        
        # Close the server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
            self.server_socket = None
        
        logger.info("VPN Server stopped")

def generate_self_signed_cert(cert_file: str, key_file: str) -> None:
    """
    Generate a self-signed certificate for testing purposes.
    
    Args:
        cert_file: Path where the certificate will be saved
        key_file: Path where the private key will be saved
    """
    if os.path.exists(cert_file) and os.path.exists(key_file):
        logger.info("Certificate files already exist, skipping generation")
        return
    
    logger.info("Generating self-signed certificate...")
    
    # This is a simplified version. In production, use a proper CA-signed certificate
    from OpenSSL import crypto
    
    # Create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)
    
    # Create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = "US"
    cert.get_subject().ST = "State"
    cert.get_subject().L = "City"
    cert.get_subject().O = "Organization"
    cert.get_subject().OU = "Organizational Unit"
    cert.get_subject().CN = "localhost"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)  # 10 years
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')
    
    # Save the certificate and key to files
    with open(cert_file, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    
    with open(key_file, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
    
    logger.info(f"Self-signed certificate generated: {cert_file}, {key_file}")

def main() -> None:
    """Main function to run the VPN server."""
    parser = argparse.ArgumentParser(description='VPN Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind the server to')
    parser.add_argument('--port', type=int, default=5000, help='Port to listen on')
    parser.add_argument('--cert', default='server.crt', help='Path to the SSL certificate file')
    parser.add_argument('--key', default='server.key', help='Path to the SSL key file')
    parser.add_argument('--generate-cert', action='store_true', help='Generate a self-signed certificate')
    
    args = parser.parse_args()
    
    # Generate self-signed certificate if requested
    if args.generate_cert:
        generate_self_signed_cert(args.cert, args.key)
    
    # Check if certificate files exist
    if not os.path.exists(args.cert) or not os.path.exists(args.key):
        logger.error(f"Certificate files not found: {args.cert}, {args.key}")
        logger.error("Run with --generate-cert to create self-signed certificates")
        return
    
    # Create and start the VPN server
    server = VPNServer(args.host, args.port, args.cert, args.key)
    
    try:
        server.start()
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
    finally:
        server.stop()

if __name__ == "__main__":
    main()