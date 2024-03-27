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
        
        self.ack_timer.reset()
        for i in range(min(self.seg_queue.qsize(), self.window_size)): 
            try:
                segment = self.seg_queue.queue[i]
            except IndexError:
                pass
            else:
                self.lossy_layer.send_segment(segment)
                seq, _, _, _, _, _ = BTCPSocket.unpack_segment_header(segment[:HEADER_SIZE])
                self.update_ack_queue(seq)

        return


    def handle_ack(self, ack_field: int, seq_field: int):
        # This functions handles an ACK message following the GBN protocol. 
        # So, if the ACK is in-order meaning not lower than the first expected ACK, remove
        # all the ACKs, which are lower than the ACK recieved, from the expected ACK queue. 

        if self.expected_ACK_queue.qsize() > 0:  # check that there are ACKs to accept
            expected_ack = self.expected_ACK_queue.queue[0]

            if (expected_ack <= ack_field and abs(expected_ack - ack_field) < MAX_DIFF) \
                or (expected_ack >= ack_field and abs(expected_ack - ack_field) > MAX_DIFF):  # ack_field >= expected_ack, taking overflow into account
                # received an ack in-order

                self.cur_tries = 0  # we got an in-order ACK so we can reset cur_tries as we conclude that the connection is still valid.
                try:
                    while not self.seg_queue.empty():
                        # Now all ACKed segments are removed from the segment queue so they will not be send again at a time-out
                        segment = self.seg_queue.queue[0]
                        seq, _, _, _, _, _ = BTCPSocket.unpack_segment_header(segment[:HEADER_SIZE])
                        if  (seq <= ack_field and abs(seq - ack_field) < MAX_DIFF) \
                            or (seq >= ack_field and abs(seq - ack_field) > MAX_DIFF):  #seq <= ack_field, taking overflow into account
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

        if seq_field == BTCPSocket.increment(self.last_received): 
            # segment recieved is in-order

            # send an ACK
            segment = BTCPSocket.build_segment(seqnum=seq_field, acknum=seq_field, ack_set=True, window=self.window_size)
            self.lossy_layer.send_segment(segment)
            self.last_received = BTCPSocket.increment(self.last_received)

            return payload
        if (seq_field < BTCPSocket.increment(self.last_received) and abs(seq_field - BTCPSocket.increment(self.last_received)) < MAX_DIFF) \
                or (seq_field > BTCPSocket.increment(self.last_received) and abs(seq_field - BTCPSocket.increment(self.last_received)) > MAX_DIFF): # retransmit the ack seq_field < last_rcvd + 1
            # received an old segment

            # send an ACK 
            segment = BTCPSocket.build_segment(seqnum=seq_field, acknum=seq_field, ack_set=True, window=self.window_size)
            self.lossy_layer.send_segment(segment)
        return     


    def build_ack_queue(self): # TODO DEZE FUNCTIE WORDT NOOIT GECALLED
        logger.warning("saying hi from the build_ack_queue")
        # Implement the logic to build the acknowledgment queue for GBN
        cpy_seg = list(self.seg_queue)
        for segment in cpy_seg:
            seq, _, _, _, _, _ = BTCPSocket.unpack_segment_header(segment[:HEADER_SIZE])
            self.expected_ACK_queue.put(seq)


    def update_ack_queue(self, seq_num: int) -> None:
        # This function puts a given sequence number, seq_num on the expected ACK queue

        try:
            self.expected_ACK_queue.put(seq_num)
        except queue.Full:
            raise LookupError ("Expected ACK queue is full.")


    def acknowledge_number(self, seq_num: int) -> None:
        # This function removes all ACKs in the expected ACK queue lower or equal to the given sequence number.
        # The function assumes the ACK queue is in-order to the extend that it will stop looking in the ACK queue
        # when it finds a sequence number bigger to seq_num (or the queue is empty). This is important for overflow.

        while not self.expected_ACK_queue.empty():
            head = self.expected_ACK_queue.queue[0]  # Get the first element without de-queueing
            
            if (head <= seq_num and abs(head - seq_num) < MAX_DIFF) \
                or (head >= seq_num and abs(head - seq_num) > MAX_DIFF): # head <= seq_num, taking overflow into account
                self.expected_ACK_queue.get()
            else:
                # found an ACK bigger than the seq_num, so stop removing ACKs
                break


    def timeout(self) -> None:  # NOTE a big part of this function can probably be moved to the packet handler
        self.window_size = max(self.window_size//2, 1)
        if self.seg_queue.empty() and self.expected_ACK_queue.empty():
            self.ack_timer.stop()
            return
        elif self.cur_tries < MAX_TRIES:
            self.send_window_segments()
            #logger.warning(f"timeout, sending {list(self.seg_queue.queue)} ")
            self.cur_tries += 1
            return
        elif self.cur_tries >= MAX_TRIES:
            # no acks received for MAX_TRIES times timeout so abandon this data sending
            self.seg_queue = queue.Queue()
            self.expected_ACK_queue = queue.Queue()
            self.ack_timer.stop()
            logger.warning("GBN: emptying queues")
            return
