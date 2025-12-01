import os
import socket
import struct
import csv
import logging
import sys
from src.protocol import Protocol


class Server:
    def __init__(self, logfile=None, debug=False):
        # Allow subclass to override logfile or default to env
        if logfile:
            self.logfile = logfile
        else:
            self.logfile = os.environ.get('LOGFILE', 'logs/server.log')

        os.makedirs(os.path.dirname(self.logfile), exist_ok=True)

        # Reset logging handlers to allow switching files between diff instances
        root = logging.getLogger()
        if root.handlers:
            for handler in root.handlers:
                root.removeHandler(handler)

        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.FileHandler(self.logfile),
                logging.StreamHandler(sys.stdout),
            ],
        )
        self.logger = logging.getLogger(__name__)

        try:
            self.host = os.environ.get('HOST', '0.0.0.0')
            self.port = int(os.environ.get('PORT', 5666))
            self.block_size = int(os.environ.get('BLOCK_SIZE', 1024))
            self.client_list_path = os.environ.get(
                'CLIENT_LIST', 'data/clients.csv'
            )

            os.makedirs(os.path.dirname(self.client_list_path), exist_ok=True)

            self.clients = []
            self.read_client_list()
        except (KeyError, ValueError) as e:
            self.logger.error(f'Configuration Error: {e}')
            raise EnvironmentError(f'Configuration Error: {e}') from e

        self.sock = None
        self.conn = None
        self.proto = Protocol(block_size=self.block_size)
        
        # bytes
        self.data_flow = 0
        self.hmac_size = 32
        self.header_size = 4
        self.gcm_iv = 12 
        self.gcm_tag = 16

    def read_client_list(self):
        """Read client list from file in disk"""
        if not os.path.exists(self.client_list_path):
            self.logger.warning(
                f'Client list {self.client_list_path} not found. Creating new one.'
            )
            self.write_client_list()
            return
        try:
            with open(self.client_list_path, mode='r', newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                self.clients = list(reader)
                self.logger.info(
                    f'Loaded {len(self.clients)} clients from listing.'
                )
        except Exception as e:
            self.logger.error(f'Failed to read client list: {e}')

    def write_client_list(self):
        """Write client list to file in disk"""
        fieldnames = ['ClientName', 'ClientIP', 'ClientPort']
        try:
            with open(self.client_list_path, mode='w', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(self.clients)
            self.logger.info('Client list updated in CSV.')
        except Exception as e:
            self.logger.error(f'Failed to write client list: {e}')

    def register_client(self, addr):
        """Register client(TAG,IP,PORT)"""
        ip, port = addr
        existing = next(
            (c for c in self.clients if c['ClientIP'] == str(ip)), None
        )
        if not existing:
            new_client = {
                'ClientName': f'Client-{len(self.clients) + 1}',
                'ClientIP': str(ip),
                'ClientPort': str(port),
            }
            self.clients.append(new_client)
            self.write_client_list()
            self.logger.info(
                f'New client registered: {new_client["ClientName"]} ({ip})'
            )
        else:
            self.logger.info(
                f'Existing client recognized: {existing["ClientName"]} ({ip})'
            )

    def communication(self):
        """Overridden by subclasses"""
        pass

    def cleartext_listen(self):
        """
        Simple TCP listening without any Handshake or Crypto.
        """
        self.logger.info(
            f'Starting CLEARTEXT Server on {self.host}:{self.port}...'
        )
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.sock.bind((self.host, self.port))
            self.sock.listen(1)
            self.logger.info('Waiting for connection...')

            self.conn, addr = self.sock.accept()
            self.logger.info(f'Connected to {addr}')
            
            self.communication()

        except socket.error as e:
            self.logger.error(f'Socket error: {e}')
        except Exception as e:
            self.logger.error(f'Error: {e}')
        finally:
            self.close()


    def aes128ctr_listen(self):
        """Server listening mode using raw (AES128-CTR) Diffie-Hellman Exchange"""
        self.logger.info(
            f'Starting on {self.host}:{self.port} with chunk size {self.block_size}'
        )
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(1)
        self.logger.info('Waiting for connection...')

        try:
            self.conn, addr = self.sock.accept()
            self.logger.info(f'Connected to {addr}')

            self.register_client(addr)
            self.logger.info('Starting Diffie-Hellman Exchange...')

            # 1. Generate own keys and GET THE RAW BYTES
            raw_server_key = self.proto.generate_256bytes_keys()

            # 2. Send RAW Public Key (256 bytes, big-endian)
            self.logger.info(
                f'Sending Server Public Key ({len(raw_server_key)} bytes)...'
            )
            self.send_raw_frame(raw_server_key)

            # 3. Receive Client Public Key (256 bytes, big-endian)
            client_pub_bytes = self.recv_raw_frame()
            if not client_pub_bytes:
                self.logger.error('Client disconnected during handshake')
                return

            # 4. Finalize Crypto Setup
            self.proto.aes128ctr_finalize_handshake(
                client_pub_bytes, is_server=True
            )
            self.logger.info(
                'Diffie-Hellman Exchange Complete. AES128-CTR Encryption Tunnel is Active.'
            )

            self.communication()

        except socket.error as e:
            self.logger.error(f'Socket error: {e}')
        except Exception as e:
            self.logger.error(f'Error during communication: {e}')
        finally:
            self.close()

    def aes128ctr_establish_connection(self, target_host, target_port):
        """Client mode: Connect to ESP32 and send key first to avoid deadlock"""
        self.logger.info(f'Connecting to {target_host}:{target_port}...')
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)  # Timeout to prevent hanging
            self.sock.connect((target_host, target_port))
            self.conn = self.sock

            self.logger.info(
                'Starting Diffie-Hellman Exchange - Initiating Handshake...'
            )

            # 1. Generate Own Key First
            raw_pub = self.proto.generate_256bytes_keys()

            # 2. SEND Client Public Key First (Avoids deadlock if ESP32 is waiting to read)
            self.logger.info(
                f'Sending client public key ({len(raw_pub)} bytes)...'
            )
            self.send_raw_frame(raw_pub)

            # 3. Receive Server Public Key
            server_pub_bytes = self.recv_raw_frame()
            if not server_pub_bytes:
                raise ConnectionError('Server disconnected during handshake')

            self.logger.info(
                f'Received server public key ({len(server_pub_bytes)} bytes)'
            )

            # 4. Finalize
            self.proto.aes128_finalize_handshake(server_pub_bytes)

            self.logger.info(
                f'Diffie-Hellman Exchange Complete - Encryption Tunnel is Active to {target_host}:{target_port}'
            )

            # Remove timeout for blocking communication loop
            self.sock.settimeout(None)

        except Exception as e:
            self.logger.error(f'Setup failed: {e}')
            self.close()
            sys.exit(1)

    def close(self):
        self.logger.info('Closing resources...')
        if self.conn:
            try:
                self.conn.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            self.conn.close()
            self.logger.info('Connection closed.')
        if self.sock:
            self.sock.close()
            self.logger.info('Socket closed.')

    def send_raw_frame(self, data):
        """Send a frame with 4-byte length header (network byte order)"""
        length = struct.pack('!I', len(data))
        self.conn.sendall(length + data)

    def recv_raw_frame(self):
        """Receive a frame with 4-byte length header (network byte order)"""
        len_bytes = self.recv_bytes(4)
        if not len_bytes:
            return None
        length = struct.unpack('!I', len_bytes)[0]
        return self.recv_bytes(length)

    def recv_bytes(self, n):
        """Receive n bytes from socket"""
        data = b''
        while len(data) < n:
            packet = self.conn.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

    def aes128ctr_send_encrypted(self, data):
        """Send AES128-CTR encrypted data in blocks (BLOCK_SIZE)"""
        encrypted_chunks = self.proto.aes128ctr_encrypt(data)
        for chunk in encrypted_chunks:
            length = struct.pack('!I', len(chunk))
            self.conn.sendall(length + chunk)

    def aes128ctr_recv_encrypted(self):
        """
        Receive AES128-CTR encrypted data in blocks (BLOCK_SIZE)
        Verify HMAC and then decrypt it
        """
        # 1. Read Length Header
        len_bytes = self.recv_bytes(4)
        if not len_bytes:
            return None
        length = struct.unpack('!I', len_bytes)[0]
        
        # 2. Read Payload (Ciphertext + MAC)
        encrypted_payload = self.recv_bytes(length)
        if not encrypted_payload:
            return None

        # 3. Verify HMAC and decrypt
        try:
            plaintext = self.proto.aes128ctr_decrypt(encrypted_payload)
            return plaintext
        except Exception as e:
            # If integrity fails, we MUST close the connection as 
            # AES-CTR counters are now desynchronized between client and server.
            self.logger.error(f"Error: {e} - Closing connection.")
            self.close()
            return None
    
    def aes256gcmrsa_listen(self):
        """Server listening mode using RSA Key Exchange and AES256-GCM"""
        self.logger.info(
            f'Starting RSA+AES256-GCM on {self.host}:{self.port}'
        )
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(1)
        self.logger.info('Waiting for connection...')

        try:
            self.conn, addr = self.sock.accept()
            self.logger.info(f'Connected to {addr}')
            self.register_client(addr)
            self.logger.info('Starting RSA Key Exchange...')

            # 1. Generate RSA Keys (2048 bit) and get PEM Public Key
            server_pem_pubkey = self.proto.generate_rsa_keys()

            # 2. Send RSA Public Key to Client
            self.logger.info(f'Sending RSA Public Key ({len(server_pem_pubkey)} bytes)...')
            self.send_raw_frame(server_pem_pubkey)

            # 3. Receive Encrypted Session Key from Client
            # Note: Client should generate random 32 bytes, encrypt with our PEM, and send.
            encrypted_session_key = self.recv_raw_frame()
            if not encrypted_session_key:
                self.logger.error('Client disconnected during handshake')
                return

            # 4. Finalize Crypto Setup (Decrypt Session Key)
            self.logger.info(f'Received Encrypted Session Key ({len(encrypted_session_key)} bytes). Decrypting...')
            self.proto.aes256gcmrsa_finalize_handshake(
                encrypted_session_key, is_server=True
            )
            
            self.logger.info(
                'RSA Exchange Complete. AES256-GCM Tunnel Active.'
            )

            self.communication()

        except socket.error as e:
            self.logger.error(f'Socket error: {e}')
        except Exception as e:
            self.logger.error(f'Error during communication: {e}')
            import traceback
            traceback.print_exc()
        finally:
            self.close()

    def aes256gcmrsa_send_encrypted(self, data):
        """Send AES256-GCM encrypted data"""
        encrypted_chunks = self.proto.aes256gcmrsa_encrypt(data)
        for chunk in encrypted_chunks:
            # We use existing send_raw_frame which handles the length header
            self.send_raw_frame(chunk)

    def aes256gcmrsa_recv_encrypted(self):
        """Receive and decrypt AES256-GCM encrypted data"""
        encrypted_payload = self.recv_raw_frame()
        if not encrypted_payload:
            return None
        
        try:
            return self.proto.aes256gcmrsa_decrypt(encrypted_payload)
        except Exception as e:
            self.logger.error(f"GCM Integrity Error: {e}")
            self.close()
            return None
