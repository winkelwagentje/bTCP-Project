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
            # initialize a header with checksum set to 0. acknum = 0 as ACK flag is false anyway.
            pseudo_header = BTCPSocket.build_segment_header(seqnum=(self.current_SN+1) % MAX_INT,acknum=0, window=self.window_size, length=len(pkt))

            # Now determine the checksum of the segment with the checksum field empty
            segment = pseudo_header + padded_pkt
            checksum = BTCPSocket.in_cksum(segment)

            # Construct the final header and segment, with correct checksum
            header = BTCPSocket.build_segment_header(seqnum=(self.current_SN+1) % MAX_INT,acknum=0, window=self.window_size, length=len(pkt), checksum=checksum)
            print("GBN: increasing the current sn to", (self.current_SN+1) % MAX_INT)
            #self.current_SN += 1
            #self.current_SN %= MAX_INT
            segment = header + padded_pkt


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
            # TODO: check the following if statement; old if is commented out
            # if int(ack_field,2) >= expected_ack:  # in-order ack
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
                # TODO: ADDED THE FOLLOWING LINE:
                self.ack_timer.reset()

        # out-of-order ack TODO TIMER?
        # now a timer must wait and at time-out window will be send again

        return

    def handle_data(self, seq_field: int, payload: bytes) -> bytes:
        # Implement the logic to handle data for GBN
        print("GBN: HANDLING DATA")
        print("GBN: pkt seq_field:", seq_field, "payload", payload, "self.last_received", self.last_received)
        if seq_field == (self.last_received + 1) % MAX_INT:      # check if the message was received in order
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
            self.last_received %= MAX_INT
            print("GBN returning payload")
            return payload
        print("GBN: SN not as expected", seq_field, self.last_received)
        if ((seq_field < (self.last_received+1)%MAX_INT and abs(seq_field - (self.last_received+1)%MAX_INT) < MAX_DIFF) \
                or (seq_field > (self.last_received+1)%MAX_INT and abs(seq_field - (self.last_received+1)%MAX_INT) > MAX_DIFF)): # retransmit the ack seq_field < last_rcvd + 1
            pseudo_header = BTCPSocket.build_segment_header(seqnum=seq_field, acknum=seq_field, syn_set=False, \
                                ack_set=True, fin_set=False, window=self.window_size, length=0, checksum=0)
            header = BTCPSocket.build_segment_header(seqnum=seq_field, acknum=seq_field, syn_set=False, \
                                ack_set=True, fin_set=False, window=self.window_size, length=0, checksum=BTCPSocket.in_cksum(pseudo_header))
            segment = header + bytes(PAYLOAD_SIZE)
            self.lossy_layer.send_segment(segment)
        #return bytes(0)
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
        if self.seg_queue.empty() and self.expected_ACK_queue.empty():
            self.ack_timer.stop()
            return
        elif self.cur_tries < MAX_TRIES:
            self.send_window_segments()
            self.cur_tries += 1
            return
        elif self.cur_tries >= MAX_TRIES:
            # no acks received for MAX_TRIES times timeout so abandon this data sending
            print("GBN ERASING EXPECTED ACKS")
            self.seg_queue = queue.Queue()
            self.expected_ACK_queue = queue.Queue()
            self.ack_timer.stop()
            return
        
