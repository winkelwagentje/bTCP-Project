from btcp.btcp_socket import BTCPSocket, BTCPStates
from btcp.lossy_layer import LossyLayer
from btcp.constants import *
from btcp.GBN import GBN

import time
import queue
import logging


logger = logging.getLogger(__name__)


class BTCPClientSocket(BTCPSocket):
    """
    bTCP client socket
    A client application makes use of the services provided by bTCP by calling
    connect, send, shutdown, and close.
    """

    def __init__(self, window, timeout):
        logger.debug("__init__ called")
        self.packet_handler = None
        super().__init__(window, timeout)
        self._lossy_layer = LossyLayer(self, CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT)

        # The data buffer used by send() to send data from the application
        # thread into the network thread. Bounded in size.
        self._sendbuf = queue.Queue(maxsize=1000)
        logger.info("Socket initialized with sendbuf size 1000")

		# max tries and tries
        self._SYN_tries = 0
        self._FIN_tries = 0


    def lossy_layer_tick_a (self):
        self.lossy_layer_tick()


    def lossy_layer_segment_received(self, segment):
        """
        Called by the lossy layer whenever a segment arrives.
        """
        logger.debug("lossy_layer_segment_received called")

        # packet_handler may not be set to a packet_handler yet and still is None 

        if len(segment) == SEGMENT_SIZE and BTCPSocket.verify_checksum(segment):
            match self._state: # just consider the transitions in the FSM where we receive anything. the rest is not handled here.
                case BTCPStates.SYN_SENT:
                    self._syn_segment_received(segment)
                case BTCPStates.ESTABLISHED:
                    self._established_segment_received(segment)
                case BTCPStates.FIN_SENT:
                    self._fin_sent_segment_received(segment)


    def _syn_segment_received(self, segment):
        """
        recv SYN|ACK -> send ACK
        """
        seq_num, ack_num, flags, _, _, _ = BTCPSocket.unpack_segment_header(segment[:HEADER_SIZE])
        if flags == fSYN+fACK and ack_num == BTCPSocket.increment(self._ISN): # check iff syn and ack flags are set, and if the ack is the expected ack.
            segment = BTCPSocket.build_segment(seqnum=ack_num, acknum=BTCPSocket.increment(seq_num), ack_set=True, window=self._window)
            self._lossy_layer.send_segment(segment)

            self._ISN_sender = seq_num  # setting sender ISN

            self.update_state(BTCPStates.ESTABLISHED)


    def _established_segment_received(self, segment):
        seq_num, ack_num, flags, _, _, _ = BTCPSocket.unpack_segment_header(segment[:HEADER_SIZE])
        if flags != fSYN + fACK:
            self.packet_handler.handle_rcvd_seg(segment)
        elif ack_num == BTCPSocket.increment(self._ISN):
                segment = BTCPSocket.build_segment(seqnum=ack_num, acknum=BTCPSocket.increment(seq_num), ack_set=True, window=self._window)
                self._lossy_layer.send_segment(segment)
    

    def _fin_sent_segment_received(self, segment):
        """
        recv ACK, process ACK
        recv FIN|ACK -> send ACK
        """
        seq_num, _, flags, _, _, _ = BTCPSocket.unpack_segment_header(segment[:HEADER_SIZE])
        if flags == fACK:
            self.packet_handler.handle_rcvd_seg(segment)
        elif flags == fFIN + fACK:
            segment = BTCPSocket.build_segment(seqnum=0, acknum=seq_num, ack_set=True, window=self._window)
            self._lossy_layer.send_segment(segment)

            self.update_state(BTCPStates.CLOSED)


    def lossy_layer_tick(self):
        """
        Called by the lossy layer whenever no segment has arrived for
        TIMER_TICK milliseconds. Defaults to 100ms, can be set in constants.py.
        """
        logger.debug("lossy_layer_tick called")

        match self._state:
            case BTCPStates.SYN_SENT:
                if self._SYN_tries > MAX_TRIES:
                    self._SYN_tries = 0
                    self.update_state(BTCPStates.CLOSED)
                else:
                    self._SYN_tries += 1

                    # re-send connecting SYN
                    segment = BTCPSocket.build_segment(seqnum=self._ISN, acknum=0, syn_set=True, window=self._window)
                    self._lossy_layer.send_segment(segment)
            case BTCPStates.ESTABLISHED:
                # the packet handler will handle all timers and will already know that there
                # have been no incomming packets, so we do not have to call anything in the socket
                pass
            case BTCPStates.FIN_SENT:
                if self._FIN_tries > MAX_TRIES:
                    self._FIN_tries = 0
                    self.update_state(BTCPStates.CLOSED)
                else:
                    self._FIN_tries += 1
                    segment = BTCPSocket.build_segment(seqnum=self.packet_handler.current_SN, acknum=0, fin_set=True, window=self._window)
                    self._lossy_layer.send_segment(segment)
            case BTCPStates.CLOSED:
                pass
        return

    def connect(self):
        if not self._state == BTCPStates.CLOSED:
            logger.debug("connect was called while not in closed. do nothing.")
            return 
        
        logger.debug("connect called")
                     
        # send 16 bit SNF, set SYN FLAG
        segment = BTCPSocket.build_segment(seqnum=self._ISN, acknum=0, syn_set=True, window=self._window)

        self._lossy_layer.send_segment(segment)
        self.update_state(BTCPStates.SYN_SENT)

        self.packet_handler = GBN(window_size=self._window, lossy_layer=self._lossy_layer, ISN=self._ISN)
        while self._state != BTCPStates.ESTABLISHED and self._state != BTCPStates.CLOSED:
            time.sleep(0.1)


    def send(self, data):
        """
        Send data originating from the application in a reliable way to the
        server.
        """
        logger.debug("send called")
        if self._state == BTCPStates.ESTABLISHED:
            return len(self.packet_handler.send_data(data=data))
        return 0


    def shutdown(self):
        """
        Perform the bTCP three-way finish to shutdown the connection.
        """
        logger.debug("shutdown called")
        
        if self._state != BTCPStates.ESTABLISHED:
            logger.debug("cannot call shutdown when connection is not ESTABLISHED")
        else:
            while not self.packet_handler.expected_ACK_queue.empty():
                time.sleep(0.1)

            segment = BTCPSocket.build_segment(seqnum=BTCPSocket.increment(self.packet_handler.current_SN), acknum=0, fin_set=True, window=self._window)
            self._lossy_layer.send_segment(segment)

            self.packet_handler.current_SN = BTCPSocket.increment(self.packet_handler.current_SN)
            self.update_state(BTCPStates.FIN_SENT)

            while not self._state == BTCPStates.CLOSED:
                time.sleep(0.1)


    def close(self):
        """
        Cleans up any internal state by at least destroying the instance of
        the lossy layer in use. Also called by the destructor of this socket.
        """
        logger.debug("close called")
        if self._lossy_layer is not None:
            self._lossy_layer.destroy()
        self._lossy_layer = None


    def __del__(self):
        """Destructor. Do not modify."""
        logger.debug("__del__ called")
        self.close()
