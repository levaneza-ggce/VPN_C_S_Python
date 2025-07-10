#!/usr/bin/env python3
"""
VPN Client-Server System

This is the main entry point for the VPN system. It provides a unified interface
to run either the client or server components.

Usage:
    python main.py server [options]
    python main.py client [options]
    python main.py --help

For detailed usage instructions, run:
    python main.py server --help
    python main.py client --help
"""

import sys
import argparse
import logging
from typing import List, Optional

# Import the client and server modules
from client import VPNClient, main as client_main
from server import VPNServer, main as server_main
from utils import print_system_info, check_dependencies, is_root

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('vpn_main')

def show_banner() -> None:
    """Display the VPN system banner."""
    banner = """
    ____   ____  _____   __  ____    ____  ______  
   / __ \ / __ \/ ___/  / / / / /   / __ \/ ____/  
  / /_/ / /_/ /\__ \   / / / / /   / /_/ / /       
 / ____/ ____/___/ /  / /_/ / /___/ ____/ /___     
/_/   /_/    /____/   \____/_____/_/    \____/     

    Python VPN Client-Server System
    """
    print(banner)

def check_requirements() -> bool:
    """
    Check if the system meets the requirements to run the VPN.

    Returns:
        bool: True if all requirements are met, False otherwise
    """
    # Check if running as root/administrator
    if not is_root():
        logger.warning("VPN requires administrator privileges to run properly")
        logger.warning("Please run the program as root/administrator")
        return False

    # Check for missing dependencies
    missing = check_dependencies()
    if missing:
        logger.warning(f"Missing dependencies: {', '.join(missing)}")
        if "cryptography" in missing:
            logger.warning("Install cryptography with: pip install cryptography")
        return False

    return True

def parse_args(args: Optional[List[str]] = None) -> argparse.Namespace:
    """
    Parse command line arguments.

    Args:
        args: Command line arguments (defaults to sys.argv[1:])

    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description='Python VPN Client-Server System',
        epilog='For more information, see the README.md file'
    )

    # Create subparsers for client and server modes
    subparsers = parser.add_subparsers(dest='mode', help='Operation mode')

    # Server mode parser
    server_parser = subparsers.add_parser('server', help='Run in server mode')
    server_parser.add_argument('--host', default='0.0.0.0', help='Host to bind the server to')
    server_parser.add_argument('--port', type=int, default=5000, help='Port to listen on')
    server_parser.add_argument('--cert', default='server.crt', help='Path to the SSL certificate file')
    server_parser.add_argument('--key', default='server.key', help='Path to the SSL key file')
    server_parser.add_argument('--generate-cert', action='store_true', help='Generate a self-signed certificate')

    # Client mode parser
    client_parser = subparsers.add_parser('client', help='Run in client mode')
    client_parser.add_argument('--host', default='localhost', help='VPN server hostname or IP address')
    client_parser.add_argument('--port', type=int, default=5000, help='VPN server port')
    client_parser.add_argument('--ca-cert', help='Path to the CA certificate file for server verification')
    client_parser.add_argument('--interactive', action='store_true', help='Run in interactive mode')

    # System info command
    parser.add_argument('--system-info', action='store_true', help='Display system information')

    # Parse arguments
    parsed_args = parser.parse_args(args)

    return parsed_args

def main() -> None:
    """Main function to run the VPN system."""
    # Show the banner
    show_banner()

    # Parse command line arguments
    args = parse_args()

    # Display system information if requested
    if args.system_info:
        print_system_info()
        return

    # Check if a mode was specified
    if not args.mode:
        logger.error("No mode specified. Use 'server' or 'client'")
        logger.info("Run 'python main.py --help' for usage information")
        return

    # Check system requirements
    if not check_requirements():
        logger.warning("System requirements not met. Some features may not work properly")
        response = input("Continue anyway? (y/n): ")
        if response.lower() != 'y':
            return

    # Run in the specified mode
    if args.mode == 'server':
        # Convert namespace to dictionary and remove 'mode'
        server_args = vars(args)
        server_args.pop('mode', None)
        server_args.pop('system_info', None)

        # Run the server
        sys.argv = [sys.argv[0]]  # Reset sys.argv to avoid conflicts with argparse
        server_main()

    elif args.mode == 'client':
        # Convert namespace to dictionary and remove 'mode'
        client_args = vars(args)
        client_args.pop('mode', None)
        client_args.pop('system_info', None)

        # Run the client
        sys.argv = [sys.argv[0]]  # Reset sys.argv to avoid conflicts with argparse
        client_main()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nVPN system stopped by user")
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)
