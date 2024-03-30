from abc import ABC, abstractmethod
import queue
from btcp.constants import PAYLOAD_SIZE, TIMER_TICK
from btcp.btcp_socket import BTCPSocket
import logging
from btcp.constants import *
from btcp.resettable_timer import ResettableTimer

logger = logging.getLogger(__name__)

"""
This file contains the PacketHandler class. The PacketHandler is an abstract class which handles packets received by a bTCP socket.
The socket must be in the established state. The PacketHandler handles incomming data-segments and ACKs and ensures the reliability of
the bTCP protocol. This is implemented in a certain concrete implementation of the class (i.e. GBN).
"""

class PacketHandler(ABC):
    def __init__(self, window_size, lossy_layer, ISN):
        self.send_base = 0                                      # send base is the head of the window; ie the index of the first element in the window to be send
        self.current_SN = BTCPSocket.increment(ISN)             # starting sequence number for the protocol; +1 because we just send 2 segments as client. (3-way handshake)
        self.expected_ACK_queue = queue.Queue()                 # ack queue keeps track of the acks to be received, and in the specified order
        self.seg_queue = queue.Queue()
        self.sender_SN = 0                                      # initialized to 0 but is updated in the handshake to the to the ISN of the other party.
                                                
        self.last_received = 0                                  # last_received is the sequence number of the last received segment
        self.window_size = window_size
        self.lossy_layer = lossy_layer
        self.ack_timer = ResettableTimer(TIMER_TICK/1000, self.timeout)

        self.cur_tries = 0                                      # tracks the number of timeouts passed by while the window has not been changed


    def send_data(self, data: bytes) -> bytes:
        """
        This function receives a data, a bytes object, turns it into 1008 byte packets. Then it makes them into segments and puts
        them on a queue. In then adds all these segments onto the already established segment queue to be sent to the receiving socket.
        """
        logger.info("send_data called")

        pkt_list = []
        init_data = data
        
        while len(data) > 0:  # converting data to packets and adding to the queue
                if len(data) >= PAYLOAD_SIZE:
                    pkt_list.append(data[:PAYLOAD_SIZE])
                    data = data[PAYLOAD_SIZE:]
                else:
                    # last packet has been created
                    pkt_list.append(data)
                    data = bytes(0)

        nr_bytes_sent = 0 

        seg_queue_ = self.build_seg_queue(pkt_list)
        while not seg_queue_.empty():  # putting all seqments in the build queue in the actual seq_queue
            try:
                self.seg_queue.put(seg_queue_.get())
                nr_bytes_sent += PAYLOAD_SIZE 
                # every segment except for the last segment contains PAYLOAD_SIZE number of bytes
                # if also the segment is put on the queue then nr_bytes_sent is bigger than it should be
                # but Python slicing handles this as my_list[len(my_list)+1] = []
            except queue.Full:
                # could not fit all segments on the queue
                pass

        self.send_window_segments() 

        return init_data[:nr_bytes_sent]


    def handle_rcvd_seg(self, segment) -> bytes:
        """ 
        A segment is recieved by a socket and unpacked. The payload and part of the unpacked header
        is given as input. This is handled by the specific instance of the handler. This function returns
        the data recieved in correct order. If a call contains not in-order data the function will return 
        an empty bytes object and depending on the specific handler it might buffer or discard the data recieved.
        """ 
        logger.info("handle_rcvd_seg called")

        seq_field, ack_field, flag_byte, window, datalen, _ = BTCPSocket.unpack_segment_header(segment[:HEADER_SIZE])
        payload = segment[HEADER_SIZE:HEADER_SIZE+datalen]

        if flag_byte & fACK:
            # received segment is an ACK
            logger.debug("received segment is an ACK")
            self.window_size = max(1, window)  # update window size
            data = self.handle_ack(ack_field)
        else:
            # received segment contains data
            logger.debug("received segment contains data")
            data = self.handle_data(seq_field, payload)

        return data

    
    def timeout(self):
        """ 
        This functions handles the case where no segments have been recieved for a time or 
        a specific has not been recieved.
        """
        logger.info("timeout called")

        # timeout is called so we assume the receiver might be very bussy, so half the window size
        self.window_size = max(self.window_size//2, 1) 

        if self.seg_queue.empty() and self.expected_ACK_queue.empty():
            # there is nothing to send or receive so the packet_handler is basically idle.
            # so we can stop the timer as to not keep getting timeouts
            self.ack_timer.stop()
        elif self.cur_tries < MAX_TRIES:
            # the number of timeouts without a sendbase change is less than MAX_TRIES
            # this means we still assume the connection is fine.
            self.send_window_segments()
            self.cur_tries += 1
        elif self.cur_tries >= MAX_TRIES:
            # no acks received for MAX_TRIES times timeout. We conclude the connection is
            # very flawed. We empty all queues and stop the timer.
            logger.warning("very bad connection detected, all data cleared.")
            self.seg_queue = queue.Queue()
            self.expected_ACK_queue = queue.Queue()
            self.ack_timer.stop()


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
        the specifc handler needs to send all segments in the window. This is also the place which
        puts new ACKs on the expected ACK queue.
        """
        pass 

    @abstractmethod
    def handle_ack(self, ack_field: int):
        """
        This function handles incoming messages with an ACK flag. It checks if the ACK is in order.
        If it is the send_base, and the ack_queue is updated in handle_ack_queue.
        If it is not in order this is handled based on the sprecific handler implementation.
        """
        pass 


    @abstractmethod
    def handle_data(self, seq_field: int, payload: bytes) -> bytes:
        '''
        This function handles incomming messages without an ACK flag, and thus this is a segment with data.
        If the data segment is in-order then this segment or possibly a buffer of data (depending on the specific handler) 
        is sent back, the socket may assume all data recieved from the packet_handler is in order.
        If the data segment in out of order the way to handle is handler specific.
        There is also an ACK send, which again is based on the specific handler.
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