import sys
from src.server import Server


class CleartextBidirectionalServer(Server):
    def __init__(self):
        super().__init__(logfile='logs/CleartextBidirectionalServer.log')
        self.data_size = self.block_size

    def communication(self):
        """
        Reads raw frames with 4-byte length headers.
        """
        while True:
            try:
                data = self.recv_raw_frame()
                if data is None:
                    self.logger.info('Client disconnected (EOF)')
                    break
                self.data_flow += self.data_size
                self.logger.info(f'Data flow: {self.data_flow} bytes')
                
                self.send_raw_frame(data)
                self.data_flow += self.data_size
                self.logger.info(f'Data flow: {self.data_flow} bytes')

            except ConnectionResetError:
                self.logger.error('Connection reset by peer')
                break
            except Exception as e:
                self.logger.error(f'Communication error: {e}')
                break


if __name__ == '__main__':
    server = CleartextBidirectionalServer()
    while True:
        try:
            server.data_flow = 0
            server.cleartext_listen()
        except KeyboardInterrupt:
            print('\n')
            server.logger.warning('Exiting due to SIGINT')
            sys.exit(0)
        except Exception as e:
            server.logger.error(f'Error: {e}')
