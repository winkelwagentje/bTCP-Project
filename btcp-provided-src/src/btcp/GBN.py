from packet_handler import PacketHandler

class GBN(PacketHandler):
    def __init__(self, window_size, ISN=0):
        super().__init__(window_size, ISN)

    def build_seg_queue(self, pkt_queue):
        # Implement the logic to build the segment queue for GBN
        pass

    def send_seq_queue(self):
        # Implement the logic to send the sequence queue for GBN
        pass 

    def handle_ack(self):
        # Implement the logic to handle acknowledgment for GBN
        pass 

    def handle_data(self):
        # Implement the logic to handle data for GBN
        pass 

    def build_ack_queue(self):
        # Implement the logic to build the acknowledgment queue for GBN
        pass
