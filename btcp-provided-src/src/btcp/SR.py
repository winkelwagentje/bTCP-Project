from btcp.packet_handler import PacketHandler
import queue
from btcp.btcp_socket import BTCPSocket
from btcp.constants import *
import logging

logger = logging.getLogger(__name__)

"""
This file contains the SR class, an implementation of the PacketHandler class, following the Selective Repeat (SR) protocol.
"""

class SR(PacketHandler):
    def __init__(self, window_size, lossy_layer, ISN):
        super().__init__(window_size=window_size, lossy_layer=lossy_layer, ISN=ISN)

    def build_seg_queue(self, pkt_list: list[bytes]) -> queue.Queue[bytes]:  # NOTE I assumed not difference with GBN
        # Given a list of data packets (of max PAYLOAD_SIZE bytes) this function creates a queue of segments, 
        # where each segment contains the data of a packet. This queue is then returned.
        logger.info("build_seg_queue called")

        seg_queue = queue.Queue()

        for pkt in pkt_list:
            if len(pkt) > PAYLOAD_SIZE:  # data payload exceeds the allocated space for data
                raise ValueError(f"data field of bTCP segment may contain a maximum of {PAYLOAD_SIZE} bytes.")

            padded_pkt = pkt + bytes(PAYLOAD_SIZE - len(pkt))  # pad a pkt with 0's such that it is PAYLOAD_SIZE bytes long

            self.current_SN = BTCPSocket.increment(self.current_SN)
            segment = BTCPSocket.build_segment(seqnum=self.current_SN, acknum=0, window=self.window_size, length=len(pkt), payload=padded_pkt)

            seg_queue.put(segment)

        return seg_queue


    def send_window_segments(self) -> None:
        # This functions sends segments which NOTE [SR specific func description]
        logger.info("send_window_segments called")

        pass


    def handle_ack(self, ack_field: int):
        # This functions handles an ACK message following the SR protocol. 
        # So, NOTE [SR specific func description]
        logger.info("handle_ack called")

        pass


    def handle_data(self, seq_field: int, payload: bytes) -> bytes:
        # The function gets a payload and a sequence number of a segment recieved by the socket.
        # We may assume the packet is not corrupted and it had no flags (meaning it is a segment containing data)
        # If the segment NOTE [SR specific func description]
        logger.info("handle_data called")

        pass


    def update_ack_queue(self, seq_num: int) -> None:  # NOTE I assumed not difference with GBN
        # This function puts a given sequence number, seq_num on the expected ACK queue
        logger.info("update_ack_queue called")

        try:
            self.expected_ACK_queue.put(seq_num)
        except queue.Full:
            raise LookupError ("Expected ACK queue is full.")


    def acknowledge_number(self, seq_num: int) -> None:
        # This function removes all ACKs that NOTE [SR specific func description]
        logger.info("acknowledge_number called")

        pass
