from abc import ABC, abstractmethod
import queue
from btcp.constants import PAYLOAD_SIZE, TIMER_TICK
from btcp.btcp_socket import BTCPSocket
import logging
from btcp.constants import *
from btcp.resettable_timer import ResettableTimer

logger = logging.getLogger(__name__)


class PacketHandler(ABC):
    def __init__(self, window_size, lossy_layer, ISN=0):
        self.send_base = 0                          # send base is the head of the window; ie the index of the first element in the window to be send
        self.current_SN = ISN + 1                   # starting sequence number for the protocol; +1 because we just send 2 segments as client. (3-way handshake)
        self.expected_ACK_queue = queue.Queue()     # ack queue keeps track of the acks to be received, and in the specified order
        self.seg_queue = queue.Queue()
        self.sender_SN = 0    # initialized to 0 but is updated in the handshake to the 
                               # to the ISN of the other party.
        self.last_received = self.sender_SN  # last_received is the sequence number of the last received segment
        self.window_size = window_size
        self.lossy_layer = lossy_layer

    def send_data(self, data: bytes) -> bytes:       # takes a byte object, turns it into 1008 byte pieces, turns those into segments, sends them
        pkt_queue = queue.Queue()                    # queue with PAYLOAD_SIZE bytes, except for the last one; possible less than PAYLOAD bytes.
        print("packet handler: sending data")
        try:
            while len(data) > 0:
                if len(data) >= PAYLOAD_SIZE:
                    pkt_queue.put(data[:PAYLOAD_SIZE])
                    data = data[PAYLOAD_SIZE:]
                else:
                    pkt_queue.put(data)
                    data = bytes(0)
        except queue.Full:
            print("packet handler: pkt queue full")
            logger.info(f"Too much data for packet queue. {pkt_queue.qsize()*PAYLOAD_SIZE} bytes loaded.")
            
        try:
            self.seg_queue = self.build_seg_queue(self, list(pkt_queue))  # TODO WEEWOO
        except queue.Full:  # TODO HALLE WEG
            print("packet handler: seg queue full")
            logger.info(f"Too much data for segment queue. {self.seg_queue.qsize()*PAYLOAD_SIZE} bytes loaded.")

        n_seg_send = min(self.seg_queue.qsize() * PAYLOAD_SIZE, len(data))  # the number of bytes loaded in queue to send

        print("packet handler: preparing to send segments")

        self.send_window_segments() 

        return data[:n_seg_send]

    def handle_rcvd_seg(self, segment) -> bytes: # handle incoming traffic; differentiate between a packet with the ACK set, and a data packet. 
        """ 
        A segment is recieved by a socket and unpacked. The payload and part of the unpacked header
        is given as input. This is handled by the specific instance of the handler. This function returns
        the data recieved in correct order. If a call contains not in-order data the function will return 
        an empty bytes object and depending on the specific handler it might buffer or discard the data recieved.
        """ 

        print("packet handler: handling a rcvd segment")
        seq_field, ack_field, flag_byte, _, _, _ = BTCPSocket.unpack_segment_header(segment[:HEADER_SIZE])
        payload = segment[HEADER_SIZE:]
         
        if flag_byte & fACK:
            print("\t it is an ACK")
            data = self.handle_ack(ack_field)
        else:
            print("\t it is a segment containing data")
            data = self.handle_data(seq_field)
        self.last_received = seq_field
        return data

    
    @abstractmethod
    def timeout(self):
        """ 
        This functions handles the case where no segments have been recieved for a time or 
        a specific has not been recieved.
        """
        pass


    @abstractmethod
    def build_seg_queue(self, pkt_list: list[bytes]) -> queue.Queue[bytes]:
        """
        This function constructs a queue of segments. These segments are constructed by the 
        specific handler and based on the data. 
        """
        pass

    @abstractmethod
    def send_window_segments(self) -> None:
        """
        This functions sends all segments within the window which the specific handler decides
        to send. This function needs to be called every time the send_base is updated and when
        the specifc handler needs to send all segments in the window.
        """
        pass 

    @abstractmethod
    def handle_ack(self, ack_field: bytes):
        """
        This function handles incoming messages with an ACK flag. It checks if the ACK is in order.
        If it is the send_base, and the ack_queue is updated in handle_ack_queue.
        If it is not in order this is handled based on the sprecific handler implementation.
        """
        pass 


    @abstractmethod
    def handle_data(self, seq_field: int):
        '''
        This function handles incomming messages without an ACK flag, and thus this is a segment with data.
        If the data segment is in-order then this segment or possibly a buffer of data (depending on the specific handler) 
        is sent back, the socket may assume all data recieved from the packet_handler is in order.
        If the data segment in out of order the way to handle is handler specific.
        There is also an ACK send, which again is based on the specific handler.
        '''
        pass 

    @abstractmethod
    def build_ack_queue(self) -> None:  
        ''' 
        the purpose of the ack queue is holding the acknumbers of the to be expected acks
        if the received ack is not equal to the first element in the queue with acks, the packets are out of order.
        Though, this function just builds the ack queue.
        '''
        pass

    @abstractmethod
    def update_ack_queue(self, seq_num: int) -> None:
        '''
        This function is called when new segments are to be pushed onto the seg_queue
        It takes an integer and pushes it onto the ack_queue
        '''
        pass

    
    @abstractmethod
    def acknowledge_number(self, seq_num: int) -> None:
        '''
        This function acknowledges the packet 'segment',
        so it does some operations on the ack_queue, depending
        on which protocol (GBN, SR, TCP) is used.
        '''
        pass