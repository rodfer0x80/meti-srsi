import sys
from src.server import Server


class AES256GCMRSABidirectionalServer(Server):
    def __init__(self):
        super().__init__(logfile='logs/AES256GCMRSABidirectionalServer.log')

    def communication(self):
        while True:
            try:
                # Receive encrypted message
                data = self.aes256gcmrsa_recv_encrypted()
                if not data:
                    self.logger.info('Client disconnected (No data received)')
                    break
                msg = data.decode('utf-8', errors='ignore')
                self.logger.info(f'RX: {msg}')
                
                # Send response
                response = f'{msg}'
                self.logger.info(f'TX: {response}')
                self.aes256gcmrsa_send_encrypted(response.encode())
            except ConnectionResetError:
                self.logger.error('Connection reset by peer')
                break
            except Exception as e:
                self.logger.error(f'Communication error: {e}')
                import traceback
                traceback.print_exc()
                break


if __name__ == '__main__':
    server = AES256GCMRSABidirectionalServer()
    while True:
        try:
            server.aes256gcmrsa_listen()
        except KeyboardInterrupt:
            print('\n')
            server.logger.warning('Exiting due to SIGINT')
            sys.exit(0)
        except Exception as e:
            server.logger.error(f'Error: {e}')
