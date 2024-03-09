from packet_handler import PacketHandler
import queue
from btcp_socket import BTCPSocket
from constants import *
from math import ceil

class GBN(PacketHandler):
    def __init__(self, window_size, ISN=0):
        super().__init__(window_size, ISN)

    def build_seg_queue(self, pkt_queue):
        # Implement the logic to build the segment queue for GBN
        seg_queue = queue.Queue()

        for pkt in pkt_queue:
            if ceil(len(pkt)/8) > PAYLOAD_SIZE:  # data payload exceeds the allocated space for data
                raise ValueError(f"data field of bTCP segment may contain a maximum of {PAYLOAD_SIZE} bytes.")

            padded_pkt = int(pkt,2) << (len(pkt) - PAYLOAD_SIZE*8)
            # initialize a header with checksum set to 0. acknum = 0 as ACK flag is false anyway.
            # the length is the ceil(len(pkt)/8) as the pkt might not be divisible by 8. We assume there are leading 0's missing.
            header = BTCPSocket.build_segment_header(seqnum=self.current_SN+1,acknum=0, window=self.window, length=ceil(len(pkt)/8)) << PAYLOAD_SIZE*8

            # Now determine the checksum of the segment with the checksum field empty
            segment = header + padded_pkt
            checksum = BTCPSocket.in_cksum(segment)

            # Construct the final header and segment, with correct checksum
            header = BTCPSocket.build_segment_header(seqnum=self.current_SN+1,acknum=0, window=self.window, length=ceil(len(pkt)/8), checksum=checksum) << PAYLOAD_SIZE*8
            self.current_SN += 1
            segment = header + padded_pkt

            seg_queue.put(segment)

        return seg_queue

    def send_window_seqments(self):
        # Implement the logic to send the sequence queue for GBN 
        # Segment sending logic in GBN: Send as many segments in the segment queue which fit in the window.

        for i in range(min(self.seg_queue.qsize(), window_size)): 
            segment = self.seg_queue.get(0)
            self.lossy_layer.send_segment(segment)

    def handle_ack(self):
        # Implement the logic to handle acknowledgment for GBN
        pass 

    def handle_data(self):
        # Implement the logic to handle data for GBN
        pass 

    def build_ack_queue(self):
        # Implement the logic to build the acknowledgment queue for GBN
        pass
