import sys
from src.server import Server


class AES256GCMRSAUnidirectionalServer(Server):
    def __init__(self):
        super().__init__(logfile='logs/AES256GCMRSAUnidirectionalServer.log')

    def communication(self):
        while True:
            try:
                data = self.aes256gcmrsa_recv_encrypted()
                if not data:
                    self.logger.info('Client disconnected (No data received)')
                    break
                msg = data.decode('utf-8', errors='ignore')
                # self.logger.info(f'RX: {msg}')
                self.data_flow += self.data_size
                self.logger.info(f'Data flow: {self.data_flow} bytes')
            except ConnectionResetError:
                self.logger.error('Connection reset by peer')
                break
            except Exception as e:
                self.logger.error(f'Communication error: {e}')
                import traceback
                traceback.print_exc()
                break


if __name__ == '__main__':
    server = AES256GCMRSAUnidirectionalServer()
    while True:
        try:
            server.data_flow = 0
            server.aes256gcmrsa_listen()
        except KeyboardInterrupt:
            print('\n')
            server.logger.warning('Exiting due to SIGINT')
            sys.exit(0)
        except Exception as e:
            server.logger.error(f'Error: {e}')
