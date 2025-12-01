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

        self.host = os.environ.get('HOST', '0.0.0.0')
        self.port = int(os.environ.get('PORT', 5666))
        self.block_size = int(os.environ.get('BLOCK_SIZE', 1460))

        self.sock = None
        self.conn = None
        self.proto = Protocol(block_size=self.block_size)

        # bytes
        self.data_flow = 0
        self.hmac_size = 32
        self.header_size = 4
        self.gcm_iv = 12
        self.gcm_tag = 16

    def communication(self):
        """Overridden by subclasses"""
        pass

    def cleartext_listen(self):
        """
        Cleartext TCP without any Handshake or Crypto.
        """
        self.logger.info(
            f'Starting CLEARTEXT on {self.host}:{self.port} with chunk size {self.block_size}'
        )
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.sock.bind((self.host, self.port))
            self.sock.listen(1)
            self.logger.info('Waiting for connection...')

            self.conn, addr = self.sock.accept()
            # Disable Nagle's
            # self.conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
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
            f'Starting AES128-CTR on {self.host}:{self.port} with chunk size {self.block_size}'
        )
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.bind((self.host, self.port))
            self.sock.listen(1)
            self.logger.info('Waiting for connection...')
            self.conn, addr = self.sock.accept()
            # Disable Nagle's
            # self.conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.logger.info(f'Connected to {addr}')

            self.logger.info('Starting Diffie-Hellman Exchange...')

            # Generate own keys and GET THE RAW BYTES
            raw_server_key = self.proto.generate_256bytes_keys()

            # Send RAW Public Key (256 bytes, big-endian)
            self.logger.info(
                f'Sending Server Public Key ({len(raw_server_key)} bytes)...'
            )
            self.send_raw_frame(raw_server_key)

            # Receive Client Public Key (256 bytes, big-endian)
            client_pub_bytes = self.recv_raw_frame()
            if not client_pub_bytes:
                self.logger.error('Client disconnected during handshake')
                return

            # Finalize Crypto Setup
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
        encrypted_payload = self.recv_raw_frame()
        if not encrypted_payload:
            return None

        # Verify HMAC and decrypt
        try:
            plaintext = self.proto.aes128ctr_decrypt(encrypted_payload)
            return plaintext
        except Exception as e:
            # If integrity fails, we MUST close the connection as
            # AES-CTR counters are now desynchronized between client and server.
            self.logger.error(f'Error: {e} - Closing connection.')
            self.close()
            return None

    def aes256gcmrsa_listen(self):
        """Server listening mode using RSA Key Exchange and AES256-GCM"""
        self.logger.info(
            f'Starting AES256-GCM on {self.host}:{self.port} with chunk size {self.block_size}'
        )
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.sock.bind((self.host, self.port))
            self.sock.listen(1)
            self.logger.info('Waiting for connection...')
            self.conn, addr = self.sock.accept()
            # Disable Nagle's
            # self.conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.logger.info(f'Connected to {addr}')

            self.logger.info('Starting RSA Key Exchange...')

            # Generate RSA Keys (2048 bit) and get PEM Public Key
            server_pem_pubkey = self.proto.generate_rsa_keys()

            # Send RSA Public Key
            self.logger.info(
                f'Sending RSA Public Key ({len(server_pem_pubkey)} bytes)...'
            )
            self.send_raw_frame(server_pem_pubkey)

            # Receive Encrypted Session Key
            # Note: Client should generate random 32 bytes, encrypt with our PEM, and send.
            encrypted_session_key = self.recv_raw_frame()
            if not encrypted_session_key:
                self.logger.error('Client disconnected during handshake')
                return

            # Decrypt Session Key
            self.logger.info(
                f'Received Encrypted Session Key ({len(encrypted_session_key)} bytes). Decrypting...'
            )
            self.proto.aes256gcmrsa_finalize_handshake(
                encrypted_session_key, is_server=True
            )

            self.logger.info('RSA Exchange Complete. AES256-GCM Tunnel Active.')

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
            self.send_raw_frame(chunk)

    def aes256gcmrsa_recv_encrypted(self):
        """Receive and decrypt AES256-GCM encrypted data"""
        encrypted_payload = self.recv_raw_frame()
        if not encrypted_payload:
            return None

        try:
            return self.proto.aes256gcmrsa_decrypt(encrypted_payload)
        except Exception as e:
            self.logger.error(f'GCM Integrity Error: {e}')
            self.close()
            return None
