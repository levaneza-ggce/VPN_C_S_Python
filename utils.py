import os
import socket
import struct
import logging
import subprocess
import platform

# fcntl is only available on Unix-like systems
if platform.system().lower() != 'windows':
    import fcntl
else:
    # Dummy fcntl for Windows
    class DummyFcntl:
        def __getattr__(self, name):
            return lambda *args, **kwargs: None
    fcntl = DummyFcntl()

# Check Python version for type annotations support
PYTHON_VERSION = tuple(map(int, platform.python_version().split('.')[:2]))
if PYTHON_VERSION >= (3, 6):
    from typing import Tuple, List, Dict, Optional, Any
else:
    # Create dummy type annotation classes for older Python versions
    class Tuple:
        def __getitem__(self, item):
            return None

    class List:
        def __getitem__(self, item):
            return None

    class Dict:
        def __getitem__(self, item):
            return None

    class Optional:
        def __getitem__(self, item):
            return None

    class Any:
        pass

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('vpn_utils')

# Constants
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

class NetworkUtils:
    @staticmethod
    def get_default_gateway() -> Optional[str]:
        """
        Get the default gateway IP address.

        Returns:
            str: The default gateway IP address or None if not found
        """
        system = platform.system().lower()

        try:
            if system == 'linux':
                with open('/proc/net/route', 'r') as f:
                    for line in f.readlines():
                        fields = line.strip().split()
                        if fields[1] == '00000000':  # Destination is 0.0.0.0
                            # Convert hex to IP address
                            gateway = socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
                            return gateway

            elif system == 'darwin':  # macOS
                output = subprocess.check_output(['route', '-n', 'get', 'default']).decode('utf-8')
                for line in output.split('\n'):
                    if 'gateway:' in line:
                        return line.split('gateway:')[1].strip()

            elif system == 'windows':
                output = subprocess.check_output(['route', 'print', '0.0.0.0']).decode('utf-8')
                for line in output.split('\n'):
                    if '0.0.0.0' in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            return parts[2]

            return None

        except Exception as e:
            logger.error(f"Error getting default gateway: {e}")
            return None

    @staticmethod
    def get_local_ip() -> Optional[str]:
        """
        Get the local IP address of the machine.

        Returns:
            str: The local IP address or None if not found
        """
        try:
            # Create a socket to determine the local IP address
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))  # Connect to Google's DNS server
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip

        except Exception as e:
            logger.error(f"Error getting local IP address: {e}")
            return None

    @staticmethod
    def is_port_available(port: int, host: str = '127.0.0.1') -> bool:
        """
        Check if a port is available on the specified host.

        Args:
            port: The port number to check
            host: The host to check (default: 127.0.0.1)

        Returns:
            bool: True if the port is available, False otherwise
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.bind((host, port))
            s.close()
            return True

        except (socket.error, OSError):
            return False

class TunnelUtils:
    @staticmethod
    def create_tun_interface(name: str = 'tun0') -> Optional[int]:
        """
        Create a TUN network interface.

        Args:
            name: The name of the TUN interface to create

        Returns:
            int: The file descriptor of the TUN interface or None if failed
        """
        system = platform.system().lower()

        if system != 'linux':
            logger.error(f"TUN interface creation is only supported on Linux, not on {system}")
            return None

        try:
            # Open the TUN/TAP device
            tun = open('/dev/net/tun', 'rb+')

            # Prepare the ioctl request
            ifr = struct.pack('16sH', name.encode(), IFF_TUN | IFF_NO_PI)

            # Create the TUN interface
            fcntl.ioctl(tun, TUNSETIFF, ifr)

            logger.info(f"Created TUN interface: {name}")
            return tun.fileno()

        except Exception as e:
            logger.error(f"Error creating TUN interface: {e}")
            return None

    @staticmethod
    def configure_tun_interface(name: str, ip: str, netmask: str) -> bool:
        """
        Configure a TUN interface with an IP address and netmask.

        Args:
            name: The name of the TUN interface
            ip: The IP address to assign to the interface
            netmask: The netmask to use

        Returns:
            bool: True if successful, False otherwise
        """
        system = platform.system().lower()

        if system != 'linux':
            logger.error(f"TUN interface configuration is only supported on Linux, not on {system}")
            return False

        try:
            # Set the interface up
            subprocess.check_call(['ip', 'link', 'set', 'dev', name, 'up'])

            # Assign IP address
            subprocess.check_call(['ip', 'addr', 'add', f"{ip}/{netmask}", 'dev', name])

            logger.info(f"Configured TUN interface {name} with IP {ip}/{netmask}")
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Error configuring TUN interface: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error configuring TUN interface: {e}")
            return False

    @staticmethod
    def add_route(network: str, netmask: str, gateway: str, interface: Optional[str] = None) -> bool:
        """
        Add a route to the routing table.

        Args:
            network: The destination network
            netmask: The netmask of the destination network
            gateway: The gateway to use
            interface: The interface to use (optional)

        Returns:
            bool: True if successful, False otherwise
        """
        system = platform.system().lower()

        try:
            if system == 'linux':
                cmd = ['ip', 'route', 'add', f"{network}/{netmask}", 'via', gateway]
                if interface:
                    cmd.extend(['dev', interface])
                subprocess.check_call(cmd)

            elif system == 'darwin':  # macOS
                cmd = ['route', 'add', '-net', network, '-netmask', netmask, gateway]
                subprocess.check_call(cmd)

            elif system == 'windows':
                cmd = ['route', 'add', network, 'mask', netmask, gateway]
                subprocess.check_call(cmd)

            else:
                logger.error(f"Unsupported operating system: {system}")
                return False

            logger.info(f"Added route to {network}/{netmask} via {gateway}")
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Error adding route: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error adding route: {e}")
            return False

class PacketUtils:
    @staticmethod
    def parse_ip_packet(packet: bytes) -> Dict[str, Any]:
        """
        Parse an IP packet and extract header information.

        Args:
            packet: The raw IP packet bytes

        Returns:
            dict: A dictionary containing the parsed IP header fields
        """
        if len(packet) < 20:  # Minimum IP header length
            return {}

        try:
            # Extract the first byte (version and header length)
            first_byte = packet[0]
            version = first_byte >> 4
            ihl = (first_byte & 0x0F) * 4  # Header length in bytes

            if version != 4:  # Only support IPv4 for now
                return {'version': version}

            # Extract other header fields
            tos = packet[1]
            total_length = struct.unpack('!H', packet[2:4])[0]
            identification = struct.unpack('!H', packet[4:6])[0]
            flags_fragment = struct.unpack('!H', packet[6:8])[0]
            ttl = packet[8]
            protocol = packet[9]
            header_checksum = struct.unpack('!H', packet[10:12])[0]
            src_ip = socket.inet_ntoa(packet[12:16])
            dst_ip = socket.inet_ntoa(packet[16:20])

            # Create the result dictionary
            result = {
                'version': version,
                'ihl': ihl,
                'tos': tos,
                'total_length': total_length,
                'identification': identification,
                'flags_fragment': flags_fragment,
                'ttl': ttl,
                'protocol': protocol,
                'header_checksum': header_checksum,
                'src_ip': src_ip,
                'dst_ip': dst_ip
            }

            # Extract options if present
            if ihl > 20:
                result['options'] = packet[20:ihl]

            # Extract payload
            result['payload'] = packet[ihl:total_length]

            return result

        except Exception as e:
            logger.error(f"Error parsing IP packet: {e}")
            return {}

    @staticmethod
    def create_ip_packet(
        src_ip: str,
        dst_ip: str,
        protocol: int,
        payload: bytes,
        identification: int = 0,
        ttl: int = 64
    ) -> bytes:
        """
        Create an IP packet with the specified parameters.

        Args:
            src_ip: The source IP address
            dst_ip: The destination IP address
            protocol: The protocol number
            payload: The packet payload
            identification: The packet identification number
            ttl: The time-to-live value

        Returns:
            bytes: The raw IP packet
        """
        try:
            # Convert IP addresses to network byte order
            src_ip_bytes = socket.inet_aton(src_ip)
            dst_ip_bytes = socket.inet_aton(dst_ip)

            # Calculate the total length
            total_length = 20 + len(payload)  # 20 bytes for the header

            # Create the header without the checksum
            header = struct.pack(
                '!BBHHHBBH4s4s',
                0x45,  # Version (4) and header length (5 words)
                0,     # Type of service
                total_length,
                identification,
                0,     # Flags and fragment offset
                ttl,
                protocol,
                0,     # Checksum (will be calculated)
                src_ip_bytes,
                dst_ip_bytes
            )

            # Calculate the checksum
            checksum = PacketUtils.calculate_checksum(header)

            # Create the header with the checksum
            header = struct.pack(
                '!BBHHHBBH4s4s',
                0x45,  # Version (4) and header length (5 words)
                0,     # Type of service
                total_length,
                identification,
                0,     # Flags and fragment offset
                ttl,
                protocol,
                checksum,
                src_ip_bytes,
                dst_ip_bytes
            )

            # Combine the header and payload
            packet = header + payload

            return packet

        except Exception as e:
            logger.error(f"Error creating IP packet: {e}")
            return b''

    @staticmethod
    def calculate_checksum(data: bytes) -> int:
        """
        Calculate the IP checksum of the given data.

        Args:
            data: The data to calculate the checksum for

        Returns:
            int: The calculated checksum
        """
        # If the data length is odd, pad with a zero byte
        if len(data) % 2 == 1:
            data += b'\x00'

        # Calculate the sum of 16-bit words
        sum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i+1]
            sum += word

        # Add the carry
        while sum >> 16:
            sum = (sum & 0xFFFF) + (sum >> 16)

        # Take the one's complement
        checksum = ~sum & 0xFFFF

        return checksum

class CryptoUtils:
    @staticmethod
    def generate_key(length: int = 32) -> bytes:
        """
        Generate a random key for encryption.

        Args:
            length: The length of the key in bytes

        Returns:
            bytes: The generated key
        """
        try:
            import os
            return os.urandom(length)
        except Exception as e:
            logger.error(f"Error generating key: {e}")
            return b''

    @staticmethod
    def encrypt(data: bytes, key: bytes) -> bytes:
        """
        Encrypt data using AES-GCM.

        Args:
            data: The data to encrypt
            key: The encryption key

        Returns:
            bytes: The encrypted data
        """
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            # Generate a random nonce
            nonce = os.urandom(12)

            # Create an AES-GCM cipher with the key
            cipher = AESGCM(key)

            # Encrypt the data
            ciphertext = cipher.encrypt(nonce, data, None)

            # Return the nonce and ciphertext
            return nonce + ciphertext

        except ImportError:
            logger.error("cryptography package not installed. Install it with: pip install cryptography")
            return data
        except Exception as e:
            logger.error(f"Error encrypting data: {e}")
            return data

    @staticmethod
    def decrypt(data: bytes, key: bytes) -> bytes:
        """
        Decrypt data using AES-GCM.

        Args:
            data: The data to decrypt (nonce + ciphertext)
            key: The decryption key

        Returns:
            bytes: The decrypted data
        """
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            # Extract the nonce and ciphertext
            nonce = data[:12]
            ciphertext = data[12:]

            # Create an AES-GCM cipher with the key
            cipher = AESGCM(key)

            # Decrypt the data
            plaintext = cipher.decrypt(nonce, ciphertext, None)

            return plaintext

        except ImportError:
            logger.error("cryptography package not installed. Install it with: pip install cryptography")
            return data
        except Exception as e:
            logger.error(f"Error decrypting data: {e}")
            return data

# Helper functions
def is_root() -> bool:
    """
    Check if the current process is running with root/administrator privileges.

    Returns:
        bool: True if running as root/administrator, False otherwise
    """
    system = platform.system().lower()

    if system == 'windows':
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:  # Unix-like systems
        return os.geteuid() == 0

def check_dependencies() -> List[str]:
    """
    Check if all required dependencies are installed.

    Returns:
        list: A list of missing dependencies
    """
    missing = []

    # Check Python packages
    try:
        import cryptography
    except ImportError:
        missing.append("cryptography")

    # Check system tools based on the platform
    system = platform.system().lower()

    if system == 'linux':
        tools = ['ip', 'ifconfig', 'route']
        for tool in tools:
            try:
                subprocess.check_call(['which', tool], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except subprocess.CalledProcessError:
                missing.append(tool)

    return missing

def print_system_info() -> None:
    """Print system information relevant to VPN operation."""
    system = platform.system()
    release = platform.release()
    version = platform.version()

    print(f"System: {system} {release} {version}")

    # Get network interfaces
    local_ip = NetworkUtils.get_default_gateway()
    gateway = NetworkUtils.get_default_gateway()

    print(f"Local IP: {local_ip}")
    print(f"Default Gateway: {gateway}")

    # Check if running as root
    if is_root():
        print("Running with administrator privileges: Yes")
    else:
        print("Running with administrator privileges: No (required for VPN functionality)")

    # Check dependencies
    missing = check_dependencies()
    if missing:
        print(f"Missing dependencies: {', '.join(missing)}")
    else:
        print("All dependencies are installed")
