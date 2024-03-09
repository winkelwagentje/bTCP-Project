from abc import ABC, abstractmethod
import queue
from constants import PAYLOAD_SIZE
from btcp_socket import BTCPSocket


class PacketHandler(ABC):
    def __init__(self, window_size, handler_type, ISN=0):
        self.send_base = 0                          # send base is the head of the window; ie the index of the first element in the window to be send
        self.current_SN = ISN + 1                   # starting sequence number for the protocol; +1 because we just send 2 segments as client. (3-way handshake)
        self.expected_ACK_queue = queue.Queue()     # ack queue keeps track of the acks to be received, and in the specified order
        self.seg_queue = queue.Queue()
        self.sender_ISN = 0    # initialized to 0 but is updated in the handshake to the 
                               # to the ISN of the other party.
        self.last_received = self.sender_ISN  # last_received is the sequence number of the last received segment
                                


        def send_data(self, data: bytes) -> None:       # takes a byte object, turns it into 1008 byte pieces, turns those into segments, sends them
            pkt_queue = queue.Queue()                   # queue with PAYLOAD_SIZE bytes, except for the last one; possible less than PAYLOAD bytes.
            while len(data) > 0:
                if len(data) >= PAYLOAD_SIZE:
                    pkt_queue.put(data[:PAYLOAD_SIZE])
                    data = data[PAYLOAD_SIZE:]
                else:
                    pkt_queue.put(data)
            
            for seg in self.build_seg_queue(self, list(pkt_queue)):
                self.seg_queue.put(seg)
            self.send_window_seqments(self) 

            return None


        def handle_rcvd_seg(self, seq_field, ack_field, ACK, payload: bytes) -> bytes: # handle incoming traffic; differentiate between a packet with the ACK set, and a data packet. 
            """ 
            A segment is recieved by a socket and unpacked. The payload and part of the unpacked header
            is given as input. This is handled by the specific instance of the handler. This function returns
            the data recieved in correct order. If a call contains not in-order data the function will return 
            an empty bytes object and depending on the specific handler it might buffer or discard the data recieved.
            """ 
            if ACK:
                return self.handle_ack(self, seq_field, ack_field, payload)
            return self.handle_data(self, seq_field, ack_field, payload)


        @abstractmethod
        def build_seg_queue(self, pkt_list):
            """
            This function constructs a queue of segments. These segments are constructed by the 
            specific handler and based on the data. 
            """
            pass

        @abstractmethod
        def send_window_seqments(self):
            """
            This functions sends all segments within the window which the specific handler decides
            to send. This function needs to be called every time the send_base is updated and when
            the specifc handler needs to send all segments in the window.
            """
            pass 

        @abstractmethod
        def handle_ack(self, seq_field, ack_field, payload):
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
        def push_ack_queue(self, seq_num: int) -> None:
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