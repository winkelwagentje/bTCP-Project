from btcp.packet_handler import PacketHandler
import queue
from btcp.btcp_socket import BTCPSocket
from btcp.constants import *
import logging

logger = logging.getLogger(__name__)

"""
This file contains the GBN class, an implementation of the PacketHandler class, following the GBN protocol.
"""

class GBN(PacketHandler):
    def __init__(self, window_size, lossy_layer, ISN):
        super().__init__(window_size=window_size, lossy_layer=lossy_layer, ISN=ISN)

    def build_seg_queue(self, pkt_list: list[bytes]) -> queue.Queue[bytes]:
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
        # This functions sends all segments, in the segment queue, which fit in the current window
        logger.info("send_window_segments called")

        self.ack_timer.reset()
        for i in range(min(self.seg_queue.qsize(), self.window_size)): 
            try:
                segment = self.seg_queue.queue[i]
            except IndexError:
                pass
            else:
                self.lossy_layer.send_segment(segment)
                seq, *_ = BTCPSocket.unpack_segment_header(segment[:HEADER_SIZE])
                self.update_ack_queue(seq)

        return


    def handle_ack(self, ack_field: int):
        # This functions handles an ACK message following the GBN protocol. 
        # So, if the ACK is in-order meaning not lower than the first expected ACK, remove
        # all the ACKs, which are lower than the ACK recieved, from the expected ACK queue. 
        logger.info("handle_ack called")

        if self.expected_ACK_queue.qsize() > 0:  # check that there are ACKs to accept
            logger.debug("expected ACK queue is not empty")
            expected_ack = self.expected_ACK_queue.queue[0]

            if BTCPSocket.le(expected_ack, ack_field):
                logger.debug("ack is in-order, removin ACKs...")
                # received an ack in-order

                self.cur_tries = 0  # we got an in-order ACK so we can reset cur_tries as we conclude that the connection is still valid.
                try:
                    while not self.seg_queue.empty():
                        # Now all ACKed segments are removed from the segment queue so they will not be send again at a time-out
                        segment = self.seg_queue.queue[0]
                        seq, *_ = BTCPSocket.unpack_segment_header(segment[:HEADER_SIZE])
                        if BTCPSocket.le(seq, ack_field):
                            self.seg_queue.get()
                        else:
                            break
                except IndexError:
                    pass

                self.acknowledge_number(ack_field)  # remove appropriate ACKs from expected ACK list
                self.ack_timer.reset()  # reset the time-out timer as ACKs have been recieved
        return


    def handle_data(self, seq_field: int, payload: bytes) -> bytes:
        # The function gets a payload and a sequence number of a segment recieved by the socket.
        # We may assume the packet is not corrupted and it had no flags (meaning it is a segment containing data)
        # If the segment is in-order, meaning the sequence number 1 higher than the last recieved sequence number,
        # we return the payload. If it is not in-order and the sequence number is lower then we expect than apparently the
        # other side still requires an ACK and thus we send this ACK. 
        logger.info("handle_data called")

        if seq_field == BTCPSocket.increment(self.last_received): 
            logger.debug("segment received is in-order, sending an ACK and returning its payload.")
            # segment recieved is in-order

            # send an ACK
            segment = BTCPSocket.build_segment(seqnum=seq_field, acknum=seq_field, ack_set=True, window=self.window_size)
            self.lossy_layer.send_segment(segment)
            self.last_received = BTCPSocket.increment(self.last_received)

            return payload
        if BTCPSocket.lt(seq_field, BTCPSocket.increment(self.last_received)):
            logger.debug("segment received was an old segment, sending an ACK.")
            # received an old segment

            # send an ACK 
            segment = BTCPSocket.build_segment(seqnum=seq_field, acknum=seq_field, ack_set=True, window=self.window_size)
            self.lossy_layer.send_segment(segment)
        return     


    def update_ack_queue(self, seq_num: int) -> None:
        # This function puts a given sequence number, seq_num on the expected ACK queue
        logger.info("update_ack_queue called")

        try:
            self.expected_ACK_queue.put(seq_num)
        except queue.Full:
            raise LookupError ("Expected ACK queue is full.")


    def acknowledge_number(self, seq_num: int) -> None:
        # This function removes all ACKs in the expected ACK queue lower or equal to the given sequence number.
        # The function assumes the ACK queue is in-order to the extend that it will stop looking in the ACK queue
        # when it finds a sequence number bigger to seq_num (or the queue is empty). This is important for overflow.
        logger.info("acknowledge_number called")

        while not self.expected_ACK_queue.empty():
            head = self.expected_ACK_queue.queue[0]  # Get the first element without de-queueing
            
            if BTCPSocket.le(head, seq_num):
                self.expected_ACK_queue.get()
            else:
                # found an ACK bigger than the seq_num, so stop removing ACKs
                break
