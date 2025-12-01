import sys
from src.server import Server


class AES128CTRBidirectionalServer(Server):
    def __init__(self):
        super().__init__(logfile='logs/AES128CTRBidirectionalServer.log')
        self.data_size = self.block_size - self.hmac_size - self.header_size

    def communication(self):
        """
        Handle encrypted communication with 
        ESP32 bidirectional communication client
        using AES-128-CTR encryption
        """
        message_counter = 0
        while True:
            try:
                # Receive encrypted message
                data = self.aes128ctr_recv_encrypted()
                if not data:
                    self.logger.info('Client disconnected (No data received)')
                    break
                msg = data.decode('utf-8', errors='ignore')
                #self.logger.info(f'RX: {msg}')
                self.data_flow += self.data_size
                self.logger.info(f'Data flow: {self.data_flow} bytes')
                
                # Send response
                response = f'{msg}'
                #self.logger.info(f'TX: {response}')
                self.aes128ctr_send_encrypted(response.encode())

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
    server = AES128CTRBidirectionalServer()
    while True:
        try:
            server.data_flow = 0
            server.aes128ctr_listen()
        except KeyboardInterrupt:
            print('\n')
            server.logger.warning('Exiting due to SIGINT')
            sys.exit(0)
        except Exception as e:
            server.logger.error(f'Error: {e}')
