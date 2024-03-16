from btcp.packet_handler import PacketHandler
import queue
from queue import Queue
from btcp.btcp_socket import BTCPSocket
from btcp.constants import *
from math import ceil

class GBN(PacketHandler):
    def __init__(self, window_size, lossy_layer, ISN=0):
        super().__init__(window_size=window_size, lossy_layer=lossy_layer, ISN=0)

    def build_seg_queue(self, pkt_list: list[bytes]) -> queue.Queue[bytes]:
        # Implement the logic to build the segment queue for GBN
        seg_queue = queue.Queue()

        for pkt in pkt_list:
            print("GBN: current SN:", self.current_SN)
            if len(pkt) > PAYLOAD_SIZE:  # data payload exceeds the allocated space for data
                raise ValueError(f"data field of bTCP segment may contain a maximum of {PAYLOAD_SIZE} bytes.")

            padded_pkt = pkt + bytes(PAYLOAD_SIZE - len(pkt))
            # initialize a header with checksum set to 0. acknum = 0 as ACK flag is false anyway.
            pseudo_header = BTCPSocket.build_segment_header(seqnum=self.current_SN+1,acknum=0, window=self.window_size, length=len(pkt))

            # Now determine the checksum of the segment with the checksum field empty
            segment = pseudo_header + padded_pkt
            checksum = BTCPSocket.in_cksum(segment)

            # Construct the final header and segment, with correct checksum
            header = BTCPSocket.build_segment_header(seqnum=self.current_SN+1,acknum=0, window=self.window_size, length=len(pkt), checksum=checksum)
            self.current_SN += 1
            segment = header + padded_pkt

            seg_queue.put(segment)

        return seg_queue

    def send_window_segments(self) -> None:
        # Implement the logic to send the sequence queue for GBN 
        # Segment sending logic in GBN: Send as many segments in the segment queue which fit in the window.

        self.ack_timer.reset()

        for i in range(min(self.seg_queue.qsize(), self.window_size)): 
            segment = self.seg_queue.get(0)
            self.lossy_layer.send_segment(segment)
            seq, _, _, _, _, _ = BTCPSocket.unpack_segment_header(segment[:HEADER_SIZE])
            self.update_ack_queue(seq)

        return

    def handle_ack(self, ack_field: int, seq_field: int):
        # Implement the logic to handle acknowledgment for GBN
        # TODO: I THINK THE FOLLOWING LINE IS NOT NECESSARY AS THE SEQUENCE NUMBER IS 
        # IRRELEVANT IN AN ACK SEGMENT plez review
        self.last_received = max(self.last_received, seq_field)  # TODO overflow
        if self.expected_ACK_queue.qsize() > 0:
            expected_ack = self.expected_ACK_queue.queue[0]
            # TODO: check the following if statement; old if is commented out
            # if int(ack_field,2) >= expected_ack:  # in-order ack
            if ack_field >= expected_ack: # TODO: following lines are replaced
                # self.acknowledge_number(int(ack_field,2))  # mark all acks with lower number as rcvd
                # self.send_base = int(ack_field, 2) + 1  # update start of the sending window 
                self.acknowledge_number(ack_field)
                self.send_base = ack_field + 1
                # TODO: ADDED THE FOLLOWING LINE:
                self.ack_timer.reset()

        # out-of-order ack TODO TIMER?
        # now a timer must wait and at time-out window will be send again

        return

    def handle_data(self, seq_field: int, payload: bytes) -> bytes:
        # Implement the logic to handle data for GBN
        print("GBN: HANDLING DATA")
        print("GBN: pkt seq_field:", seq_field, "payload", payload, "self.last_received", self.last_received)
        if seq_field == self.last_received + 1:      # check if the message was received in order
            print("GBN: packet in-order")
            # TODO: CHECK IF THE ABOVE + 2 INSTEAD OF + 1 MAKES SENSE
            # I THINK IT MAKES SENSE BECAUSE THE CLIENT TAKES 2 MESSAGES FOR THE HANDSHAKE IN AN IDEAL WORLD
            # THIS HAS EVERYTHING TO DO WITH HOW WE INITIALIZE LAST RECEIVED
            pseudo_header = BTCPSocket.build_segment_header(seqnum=seq_field, acknum=seq_field, syn_set=False, \
                                ack_set=True, fin_set=False, window=self.window_size, length=0, checksum=0)
            header = BTCPSocket.build_segment_header(seqnum=seq_field, acknum=seq_field, syn_set=False, \
                                ack_set=True, fin_set=False, window=self.window_size, length=0, checksum=BTCPSocket.in_cksum(pseudo_header))
            segment = header + bytes(PAYLOAD_SIZE)
            self.lossy_layer.send_segment(segment)
            self.last_received += 1
            return payload
        print("GBN: SN not as expected", seq_field, self.last_received)
        return bytes(0) 

    def build_ack_queue(self):
        # Implement the logic to build the acknowledgment queue for GBN
        cpy_seg = list(self.seg_queue)
        for segment in cpy_seg:
            seq, _, _, _, _, _ = BTCPSocket.unpack_segment_header(segment[:HEADER_SIZE])
            self.expected_ACK_queue.put(seq)


    def update_ack_queue(self, seq_num: int):
        self.expected_ACK_queue.put(seq_num)

    def acknowledge_number(self, seq_num: int):      # GBN is cumulative so pop all numbers <= seq_num
        while not self.expected_ACK_queue.empty():
            head = self.expected_ACK_queue.queue[0]  # Get the first element without dequeuing
            if head <= seq_num:
                # Pop the element from the queue
                self.expected_ACK_queue.get()
            else:
                break

    def timeout(self):
        if self.seg_queue.empty() and self.expected_ACK_queue.empty():
            self.ack_timer.stop()
            return
        else:
            self.send_window_segments()
            return
        
