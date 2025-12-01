import os
import hashlib
import hmac
import struct

from cryptography.hazmat.primitives.asymmetric import dh, rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class IntegrityError(Exception):
    """Raised when an HMAC signature fails verification."""

    def __init__(self, message='HMAC signature verification failed'):
        self.message = message
        super().__init__(self.message)


class Protocol:
    def __init__(self, block_size=0):
        # RFC 3526 Group 14
        P_HEX = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF'
        P = int(P_HEX, 16)
        G = 2

        self.backend = default_backend()
        self.private_key = None
        self.public_key = None
        self.block_size = int(block_size)
        self.pn = dh.DHParameterNumbers(p=P, g=G)

        # AES-CTR state: manage counter manually
        self.aes_key = None
        self.hmac_key = None
        self.tx_nonce_base = None
        self.rx_nonce_base = None
        
        self.rsa_private_key = None
        self.rsa_public_key = None
        self.gcm_cipher = None # Instance of AESGCM
        self.session_key = None # 32 bytes (256 bits)

        # Persistent encryptor/decryptor
        self.encryptor = None
        self.decryptor = None

    def generate_256bytes_keys(self):
        """Generate Diffie-Hellman key pair and return raw public key (256 bytes, big-endian)"""
        self.parameters = self.pn.parameters(self.backend)
        self.private_key = self.parameters.generate_private_key()
        self.public_key = self.private_key.public_key()
        y = self.public_key.public_numbers().y
        return y.to_bytes(256, 'big')

    def _aes128ctr_derive_keys(self, shared_secret):
        """
        Simple key derivation using SHA256
        Returns: (aes_key_32bytes, tx_nonce_8bytes, rx_nonce_8bytes)

        Both sides derive the same values, but they interpret them oppositely:
        - Bytes [32:40]: Nonce A (Server uses as TX, ESP32 uses as RX)
        - Bytes [40:48]: Nonce B (Server uses as RX, ESP32 uses as TX)
        """
        hash1 = hashlib.sha256(shared_secret).digest()
        hash2 = hashlib.sha256(hash1).digest()
        hash3 = hashlib.sha256(hash2).digest()
        derived = hash1 + hash2 + hash3

        aes_key = derived[0:16]
        nonce_a = derived[32:40]
        nonce_b = derived[40:48]
        hmac_key = derived[64:96]

        # For SERVER: tx_nonce = nonce_a, rx_nonce = nonce_b
        # For ESP32: tx_nonce = nonce_b, rx_nonce = nonce_a
        # This is handled at cipher initialization level
        return aes_key, nonce_a, nonce_b, hmac_key

    def aes128ctr_finalize_handshake(self, peer_raw_bytes, is_server=False):
        """
        Complete DH handshake.
        'is_server': argument is ignored here because the ESP32 firmware
        has hardcoded Nonce assignments (Tx=A, Rx=B).
        To match it, Python must ALWAYS be (Tx=B, Rx=A).
        """
        peer_y = int.from_bytes(peer_raw_bytes, 'big')
        peer_public_numbers = dh.DHPublicNumbers(peer_y, self.pn)
        peer_public_key = peer_public_numbers.public_key(self.backend)
        shared_secret = self.private_key.exchange(peer_public_key)

        # Derive keys
        self.aes_key, nonce_a, nonce_b, self.hmac_key = (
            self._aes128ctr_derive_keys(shared_secret)
        )

        # ESP32 Hardcoded: Tx = Nonce A, Rx = Nonce B
        # Python Must Be:  Tx = Nonce B, Rx = Nonce A
        self.tx_nonce_base = nonce_b
        self.rx_nonce_base = nonce_a

        # Initialize CTR ciphers with counter starting at 0
        tx_full_nonce = self.tx_nonce_base + b'\x00' * 8
        rx_full_nonce = self.rx_nonce_base + b'\x00' * 8

        self.encryptor = Cipher(
            algorithms.AES(self.aes_key),
            modes.CTR(tx_full_nonce),
            backend=self.backend,
        ).encryptor()

        self.decryptor = Cipher(
            algorithms.AES(self.aes_key),
            modes.CTR(rx_full_nonce),
            backend=self.backend,
        ).decryptor()

    def aes128ctr_encrypt(self, data):
        """Encrypt data using AES-128-CTR with PERSISTENT encryptor"""
        if self.encryptor is None:
            raise RuntimeError('Handshake not completed')

        # Encrypt entire message at once to keep CTR counter in sync
        encrypted = self.encryptor.update(data)

        # Integrity check
        mac = hmac.new(self.hmac_key, encrypted, hashlib.sha256).digest()

        return [encrypted + mac]

    def aes128ctr_decrypt(self, data):
        """Decrypt data using AES-128-CTR with PERSISTENT decryptor"""
        if self.decryptor is None:
            raise RuntimeError('Handshake not completed')

        MAC_LEN = 32
        if len(data) < MAC_LEN:
            raise IntegrityError('Payload too short to contain MAC')

        encrypted = data[:-MAC_LEN]
        received_mac = data[-MAC_LEN:]

        expected_mac = hmac.new(
            self.hmac_key, encrypted, hashlib.sha256
        ).digest()
        if not hmac.compare_digest(received_mac, expected_mac):
            raise IntegrityError('HMAC verification failed')

        return self.decryptor.update(encrypted)

    def generate_rsa_keys(self):
        """
        Generate RSA Keypair (2048 bit).
        Returns: PEM encoded Public Key bytes (to send to client).
        """
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=self.backend
        )
        self.rsa_public_key = self.rsa_private_key.public_key()

        pem = self.rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem

    def aes256gcmrsa_finalize_handshake(self, received_bytes, is_server=True):
        """
        Finalize handshake.
        If Server: 'received_bytes' is the AES Session Key encrypted with our RSA Public Key.
        """
        if is_server:
            # Decrypt the session key sent by the client
            try:
                self.session_key = self.rsa_private_key.decrypt(
                    received_bytes,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )
            except Exception as e:
                raise IntegrityError(f'RSA Decryption failed: {e}')

            if len(self.session_key) != 32:
                raise IntegrityError(
                    f'Invalid Session Key length: {len(self.session_key)}'
                )

            # Initialize AES-GCM
            self.gcm_cipher = AESGCM(self.session_key)
        else:
            # Client implementation would go here (Encrypt generated key with server pub key)
            pass

    def aes256gcmrsa_encrypt(self, data):
        """
        Encrypts data using AES-256-GCM.
        Generates a unique 12-byte Nonce per packet.
        Format: [Nonce (12)] + [Ciphertext + Tag]
        """
        if self.gcm_cipher is None:
            raise RuntimeError('Handshake not completed')

        # GCM requires a unique nonce for every encryption
        nonce = os.urandom(12)

        # AESGCM.encrypt returns (ciphertext + tag) appended
        ciphertext_with_tag = self.gcm_cipher.encrypt(nonce, data, None)

        return [nonce + ciphertext_with_tag]

    def aes256gcmrsa_decrypt(self, data):
        """
        Decrypts data using AES-256-GCM.
        Expects: [Nonce (12)] + [Ciphertext + Tag]
        """
        if self.gcm_cipher is None:
            raise RuntimeError('Handshake not completed')

        if len(data) < 28:  # 12 (Nonce) + 16 (Tag) minimum
            raise IntegrityError('Payload too short for GCM')

        nonce = data[:12]
        ciphertext_with_tag = data[12:]

        try:
            plaintext = self.gcm_cipher.decrypt(
                nonce, ciphertext_with_tag, None
            )
            return plaintext
        except Exception:
            raise IntegrityError('GCM Decryption/Tag Check failed')
