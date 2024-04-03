from btcp.packet_handler import PacketHandler
import queue
from btcp.btcp_socket import BTCPSocket
from btcp.constants import *
import logging
import functools

logger = logging.getLogger(__name__)

"""
This file contains the SR class, an implementation of the PacketHandler class, following the Selective Repeat (SR) protocol.
"""

class SR(PacketHandler):
    def __init__(self, window_size, lossy_layer, ISN):
        super().__init__(window_size=window_size, lossy_layer=lossy_layer, ISN=ISN)

        self.data_recvd_buffer = queue.Queue()  # tuples of data and SNs


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
        # This functions sends segments which NOTE [SR specific func description]
        logger.info("send_window_segments called")

        self.ack_timer.reset()
        if not self.seg_queue.empty():
            max_seq, *_ = BTCPSocket.unpack_segment_header(self.seg_queue.queue[0][:HEADER_SIZE])
            max_seq = BTCPSocket.increment(max_seq, self.window_size)
            for i in range(min(self.seg_queue.qsize(), self.window_size)): 
                try:
                    segment = self.seg_queue.queue[i]
                except IndexError:
                    pass
                else:
                    seq, *_ = BTCPSocket.unpack_segment_header(segment[:HEADER_SIZE])
                    if BTCPSocket.lt(seq, max_seq):
                        self.lossy_layer.send_segment(segment)
                        self.update_ack_queue(seq)


    def handle_ack(self, ack_field: int):
        # This functions handles an ACK message following the SR protocol. 
        # So, NOTE [SR specific func description]
        logger.info("handle_ack called")
        logger.debug(f"before: {len(self.seg_queue.queue)}")

        if not self.expected_ACK_queue.empty():
            if ack_field in self.expected_ACK_queue.queue:
                
                # now remove from the seg_queue
                new_q = queue.Queue()
                logger.debug("hi")

                while not self.seg_queue.empty():
                    segment = self.seg_queue.get()
                    seq, *_ = BTCPSocket.unpack_segment_header(segment[:HEADER_SIZE])
                    logger.debug("doei")
                    if seq != ack_field:
                        new_q.put(segment)
                self.seg_queue = new_q

                self.acknowledge_number(ack_field)

        logger.debug(f"after: {len(self.seg_queue.queue)}")
        pass


    def handle_data(self, seq_field: int, payload: bytes) -> bytes:
        # The function gets a payload and a sequence number of a segment recieved by the socket.
        # We may assume the packet is not corrupted and it had no flags (meaning it is a segment containing data)
        # If the segment NOTE [SR specific func description]
        logger.info("handle_data called")
        logger.debug(f"SNF {seq_field}, payload {payload[:10]}, lst rcvd {self.last_received}")

        if BTCPSocket.ge(seq_field, BTCPSocket.increment(self.last_received)): 
            logger.debug("segment received is in-order, sending an ACK and returning its payload.")
            # segment recieved is in-order

            # send an ACK
            segment = BTCPSocket.build_segment(seqnum=seq_field, acknum=seq_field, ack_set=True, window=self.window_size)
            self.lossy_layer.send_segment(segment)
            # self.last_received = BTCPSocket.increment(self.last_received)

            self.data_recvd_buffer.put((payload, seq_field))
        else:
            logger.debug("segment received was an old segment, sending an ACK.")
            # received an old segment

            # send an ACK 
            segment = BTCPSocket.build_segment(seqnum=seq_field, acknum=seq_field, ack_set=True, window=self.window_size)
            self.lossy_layer.send_segment(segment)

        logger.debug(f"data rcvd buffer {self.data_recvd_buffer.queue}")
        #  sort buffer and return all in_order
        buffer = sorted(self.data_recvd_buffer.queue, key=functools.cmp_to_key(lambda x, y: 1 if BTCPSocket.ge(x,y) else (-1 if BTCPSocket.lt(x,y) else 0)))
        logger.debug(f"extracted buffer list, sorted {buffer}")
        
        in_order_data = bytes(0)
        if len(buffer) > 0:
            logger.debug("buffer len > 0")
            for buf in buffer:
                logger.debug(f"buf {buf}, lst rcvd {self.last_received}")
                if buf[1] == BTCPSocket.increment(self.last_received):
                    in_order_data += buf[0]
                    self.last_received = BTCPSocket.increment(self.last_received)
                else:
                    break
        
        logger.debug(f"all data that is fit to return {in_order_data}")

        buffer = list(filter(lambda x : BTCPSocket.gt(x[1], self.last_received), buffer))

        logger.debug(f"reduced buffer {buffer}")
            
        self.data_recvd_buffer = queue.Queue()
        for buf in buffer:
            self.data_recvd_buffer.put(buf)

        logger.debug(f"updated data rcvd buffer {self.data_recvd_buffer.queue}")

        logger.debug(f"returning {in_order_data}")
        return in_order_data if in_order_data != bytes(0) else None


    def update_ack_queue(self, seq_num: int) -> None:
        # This function puts a given sequence number, seq_num on the expected ACK queue
        logger.info("update_ack_queue called")

        try:
            self.expected_ACK_queue.put(seq_num)
        except queue.Full:
            raise LookupError ("Expected ACK queue is full.")


    def acknowledge_number(self, seq_num: int) -> None:
        # This function removes all ACKs that NOTE [SR specific func description]
        logger.info("acknowledge_number called")
        logger.debug(f"size expctd ack q before ackn_num {len(self.expected_ACK_queue.queue)}")

        if not self.expected_ACK_queue.empty() and seq_num in self.expected_ACK_queue.queue:
            if seq_num == self.expected_ACK_queue.queue[0]:
                self.cur_tries = 0  # send_base is changed
                self.ack_timer.reset()

            self.expected_ACK_queue = self.remove_from_queue(self.expected_ACK_queue, seq_num)
        logger.debug(f"size expctd ack q after ackn_num {len(self.expected_ACK_queue.queue)}")
        return


    @staticmethod
    def remove_from_queue(q: queue, val) -> queue:
        logger.debug(f"1quue: {q.queue}, val: {val}")
        new_q = queue.Queue()
        new_list = filter(lambda x : x != val, list(q.queue))
        for elem in new_list:
            new_q.put(elem)

        logger.debug(f"2quue: {q.queue}, val: {val}")
        return new_q

        
            
        


