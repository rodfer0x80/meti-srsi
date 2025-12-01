import sys
import os

from src.server import Server


class CleartextUnidirectionalServer(Server):
    def __init__(self):
        super().__init__(logfile='logs/CleartextUnidirectionalServer.log')
        self.data_size = self.block_size - self.header_size
        self.debug = int(os.environ.get('DEBUG', 0))

    def communication(self):
        """
        Reads raw frames with 4-byte length headers.
        """
        self.data_flow = 0
        self.logger.info(
            f'Running CLEARTEXT with block size {self.block_size} bytes at total {self.data_size} bytes data'
        )
        while True:
            try:
                data = self.recv_raw_frame()
                if data is None:
                    self.logger.info('Client disconnected (EOF)')
                    break

                self.data_flow += self.data_size

                if self.debug == 1:
                    self.logger.info(f"RX: {data}")
                
            except ConnectionResetError:
                self.logger.error('Connection reset by peer')
                break
            except Exception as e:
                self.logger.error(f'Communication error: {e}')
                break
        self.logger.info(f'Data: {self.data_flow} bytes')


if __name__ == '__main__':
    server = CleartextUnidirectionalServer()
    while True:
        try:
            server.cleartext_listen()
        except KeyboardInterrupt:
            print('\n')
            server.logger.warning('Exiting due to SIGINT')
            sys.exit(0)
        except Exception as e:
            server.logger.error(f'Error: {e}')
