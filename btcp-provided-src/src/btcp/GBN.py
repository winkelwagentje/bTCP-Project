from packet_handler import PacketHandler
import queue
from btcp_socket import BTCPSocket
from constants import *
from math import ceil

class GBN(PacketHandler):
    def __init__(self, window_size, ISN=0):
        super().__init__(window_size, ISN)

    def build_seg_queue(self, pkt_list: list[bytes]) -> Queue[bytes]:
        # Implement the logic to build the segment queue for GBN
        seg_queue = queue.Queue()

        for pkt in pkt_list:
            if ceil(len(pkt)/8) > PAYLOAD_SIZE:  # data payload exceeds the allocated space for data
                raise ValueError(f"data field of bTCP segment may contain a maximum of {PAYLOAD_SIZE} bytes.")

            padded_pkt = pkt + b'0'*(len(pkt) - PAYLOAD_SIZE*8)
            # initialize a header with checksum set to 0. acknum = 0 as ACK flag is false anyway.
            # the length is the ceil(len(pkt)/8) as the pkt might not be divisible by 8. We assume there are leading 0's missing.
            header = BTCPSocket.build_segment_header(seqnum=self.current_SN+1,acknum=0, window=self.window, length=ceil(len(pkt)/8))

            # Now determine the checksum of the segment with the checksum field empty
            segment = header + padded_pkt
            checksum = BTCPSocket.in_cksum(segment)

            # Construct the final header and segment, with correct checksum
            header = BTCPSocket.build_segment_header(seqnum=self.current_SN+1,acknum=0, window=self.window, length=ceil(len(pkt)/8), checksum=checksum)
            self.current_SN += 1
            segment = header + padded_pkt

            seg_queue.put(segment)

        return seg_queue

    def send_window_segments(self) -> None:
        # Implement the logic to send the sequence queue for GBN 
        # Segment sending logic in GBN: Send as many segments in the segment queue which fit in the window.

        for i in range(min(self.seg_queue.qsize(), window_size)): 
            segment = self.seg_queue.get(0)
            self.lossy_layer.send_segment(segment)
            seq, _, _, _, _, _ = BTCPSocket.unpack_segment_header(segment[:HEADER_SIZE])
            self.update_ack_queue(seq)

        return

    def handle_ack(self, ack_field: bytes):
        # Implement the logic to handle acknowledgment for GBN

        if self.ack_queue.qsize() > 0:
            expected_ack = self.ack_queue.queue[0]
            if int(ack_field,2) >= expected_ack:  # in-order ack
                self.acknowledge_number(int(ack_field,2))  # mark all acks with lower number as rcvd

        # out-of-order ack
        # now a timer must wait and at time-out window will be send again

        return

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
