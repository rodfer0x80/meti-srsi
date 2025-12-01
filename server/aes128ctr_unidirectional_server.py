import sys
import os

from src.server import Server


class AES128CTRUnidirectionalServer(Server):
    def __init__(self):
        super().__init__(logfile='logs/AES128CTRUnidirectionalServer.log')
        self.data_size = self.block_size - self.hmac_size - self.header_size
        self.debug = int(os.environ.get('DEBUG', 0))

    def communication(self):
        """
        Handle encrypted communication with 
        ESP32 bidirectional communication client
        using AES-128-CTR encryption
        """
        self.data_flow = 0
        self.logger.info(
            f'Running AES128 with block size {self.block_size} bytes at total {self.data_size} bytes data'
        )
        while True:
            try:
                data = self.aes128ctr_recv_encrypted()
                if not data:
                    self.logger.info('Client disconnected (No data received)')
                    break
                self.data_flow += self.data_size
                if self.debug:
                    msg = data.decode('utf-8', errors='ignore')
                    self.logger.info(f'RX: {msg}')
            except ConnectionResetError:
                self.logger.error('Connection reset by peer')
                break
            except Exception as e:
                self.logger.error(f'Communication error: {e}')
                import traceback
                traceback.print_exc()
                break
        self.logger.info(f'Data: {self.data_flow} bytes')


if __name__ == '__main__':
    server = AES128CTRUnidirectionalServer()
    while True:
        try:
            server.aes128ctr_listen()
        except KeyboardInterrupt:
            print('\n')
            server.logger.warning('Exiting due to SIGINT')
            sys.exit(0)
        except Exception as e:
            server.logger.error(f'Error: {e}')
