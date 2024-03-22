from btcp.packet_handler import PacketHandler
import queue
from btcp.btcp_socket import BTCPSocket
from btcp.constants import *

class GBN(PacketHandler):
    def __init__(self, window_size, lossy_layer, ISN):
        super().__init__(window_size=window_size, lossy_layer=lossy_layer, ISN=ISN)

    def build_seg_queue(self, pkt_list: list[bytes]) -> queue.Queue[bytes]:
        # Implement the logic to build the segment queue for GBN
        seg_queue = queue.Queue()

        for pkt in pkt_list:
            if len(pkt) > PAYLOAD_SIZE:  # data payload exceeds the allocated space for data
                raise ValueError(f"data field of bTCP segment may contain a maximum of {PAYLOAD_SIZE} bytes.")

            padded_pkt = pkt + bytes(PAYLOAD_SIZE - len(pkt))

            self.current_SN = BTCPSocket.increment(self.current_SN)
            segment = BTCPSocket.build_segment(seqnum=self.current_SN, acknum=0, window=self.window_size, length=len(pkt), payload=padded_pkt)

            seg_queue.put(segment)

        return seg_queue

    def send_window_segments(self) -> None:
        # Implement the logic to send the sequence queue for GBN 
        # Segment sending logic in GBN: Send as many segments in the segment queue which fit in the window.

        self.ack_timer.reset()

        for i in range(min(self.seg_queue.qsize(), self.window_size)): 
            try:
                segment = self.seg_queue.queue[i]
            except IndexError:
                pass
            self.lossy_layer.send_segment(segment)
            seq, _, _, _, _, _ = BTCPSocket.unpack_segment_header(segment[:HEADER_SIZE])
            self.update_ack_queue(seq)

        return

    def handle_ack(self, ack_field: int, seq_field: int):
        # Implement the logic to handle acknowledgment for GBN
        if self.expected_ACK_queue.qsize() > 0:
            expected_ack = self.expected_ACK_queue.queue[0]

            if ack_field >= expected_ack: 
                # received an ack in-order, so connection is still valid and we can reset cur_tries for this sending window
                self.cur_tries = 0
                try:
                    while not self.seg_queue.empty():
                        segment = self.seg_queue.queue[0]
                        seq, _, _, _, _, _ = BTCPSocket.unpack_segment_header(segment[:HEADER_SIZE])
                        if seq <= ack_field:
                            self.seg_queue.get()
                        else:
                            break
                except IndexError:
                    pass

                self.acknowledge_number(ack_field)
                self.ack_timer.reset()
        return

    def handle_data(self, seq_field: int, payload: bytes) -> bytes:
        # Implement the logic to handle data for GBN
        if seq_field == BTCPSocket.increment(self.last_received):      # check if the message was received in order
            segment = BTCPSocket.build_segment(seqnum=seq_field, acknum=seq_field, ack_set=True, window=self.window_size)
            self.lossy_layer.send_segment(segment)
            self.last_received = BTCPSocket.increment(self.last_received)
            return payload
        if (seq_field < BTCPSocket.increment(self.last_received) and abs(seq_field - BTCPSocket.increment(self.last_received)) < MAX_DIFF) \
                or (seq_field > BTCPSocket.increment(self.last_received) and abs(seq_field - BTCPSocket.increment(self.last_received) > MAX_DIFF)): # retransmit the ack seq_field < last_rcvd + 1
            segment = BTCPSocket.build_segment(seqnum=seq_field, acknum=seq_field, ack_set=True, window=self.window_size)
            self.lossy_layer.send_segment(segment)
        return     

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
        self.window_size = max(self.window_size//2, 1)
        if self.seg_queue.empty() and self.expected_ACK_queue.empty():
            self.ack_timer.stop()
            return
        elif self.cur_tries < MAX_TRIES:
            self.send_window_segments()
            self.cur_tries += 1
            return
        elif self.cur_tries >= MAX_TRIES:
            # no acks received for MAX_TRIES times timeout so abandon this data sending
            self.seg_queue = queue.Queue()
            self.expected_ACK_queue = queue.Queue()
            self.ack_timer.stop()
            return
        
