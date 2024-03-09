from packet_handler import PacketHandler
from btcp_socket import BTCPSocket
from constants import PAYLOAD_SIZE

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

    def handle_data(self, seq_field: int):
        # Implement the logic to handle data for GBN
        if seq_field == super().last_received + 1:      # check if the message was received in order
            pseudo_header = BTCPSocket.build_segment_header(seqnum=seq_field, acknum=seq_field, syn_set=False, \
                                ack_set=True, fin_set=False, length=0, checksum=0)
            header = BTCPSocket.build_segment_header(seqnum=seq_field, acknum=seq_field, syn_set=False, \
                                ack_set=True, fin_set=False, length=0, checksum=BTCPSocket.in_cksum(pseudo_header))
            segment = header + bytes(PAYLOAD_SIZE)
            # send the payload
        pass 

    def build_ack_queue(self):
        # Implement the logic to build the acknowledgment queue for GBN
        cpy_seg = list(self.seg_queue)
        for segment in cpy_seg:
            seq, _, _, _, _, _ = BTCPSocket.unpack_segment_header(segment[:10])
            super().expected_ACK_queue.put(seq)


    def update_ack_queue(self, seq_num):
        super().expected_ACK_queue.put(seq_num)

    def acknowledge_number(self, seq_num):      # GBN is cumulative so pop all numbers <= seq_num
        while not super().expected_ACK_queue.empty():
            head = super().expected_ACK_queue.queue[0]  # Get the first element without dequeuing
            if head <= seq_num:
                # Pop the element from the queue
                super().expected_ACK_queue.get()
            else:
                break
