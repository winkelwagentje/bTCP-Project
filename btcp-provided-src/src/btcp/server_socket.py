from btcp.btcp_socket import BTCPSocket, BTCPStates
from btcp.lossy_layer import LossyLayer
from btcp.constants import *
from btcp.GBN import GBN

import queue
import time
import logging


logger = logging.getLogger(__name__)


class BTCPServerSocket(BTCPSocket):
    def __init__(self, window, timeout):
        logger.debug("__init__() called.")
        self.packet_handler = None
        super().__init__(window, timeout)
        self._lossy_layer = LossyLayer(self, SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT)

        self._recvbuf = queue.Queue(maxsize=1000)
        self._fin_received_in_closing = False
        logger.info("Socket initialized with recvbuf size 1000")

        
        # Number of tries to establish
        self._SYN_tries = 0
        self._accept_tries = 0

    def lossy_layer_tick_a (self):
        self.lossy_layer_tick()

    def lossy_layer_segment_received(self, segment):
        logger.debug("lossy_layer_segment_received called")
        # TODO: packet_handler may not be set to a packet_handler yet and still is None

        if len(segment) == SEGMENT_SIZE and self.verify_checksum(segment):
                match self._state:
                    case BTCPStates.ACCEPTING: 
                        self._accepting_segment_received(segment)
                    case BTCPStates.CLOSING: 
                        # for now we ignore past FIN received segments
                        self._closing_segment_received(segment)
                    case BTCPStates.SYN_RCVD:
                        self._syn_segment_received(segment)
                    case BTCPStates.ESTABLISHED:
                        self._established_segment_received(segment)

        return


    def _accepting_segment_received(self, segment):
        logger.info("accepting a segment")

        seq_num, _, flags, _, _, _ = BTCPSocket.unpack_segment_header(segment[:HEADER_SIZE])
        # Slice data from incoming segment.


        # If the segment has a SYN flag we reply with a SYN|ACK to start a connection
        if flags & fSYN:  # SYN flag is set
            # update variables consistent with handshake
            self.update_state(BTCPStates.SYN_RCVD)
            self.sender_SN = seq_num
            self._ISN_sender = seq_num  # setting sender ISN
            self.packet_handler.current_SN = BTCPSocket.increment(self.packet_handler.current_SN)
            self.packet_handler.last_received = seq_num

            # construct segment
            segment = BTCPSocket.build_segment(seqnum=self._ISN, acknum=BTCPSocket.increment(seq_num),syn_set=True, ack_set=True, window=self._window)
            self._lossy_layer.send_segment(segment)
        return


    def _closing_segment_received(self, segment):

        logger.debug("_closing_segment_received called")
        logger.info("Segment received in CLOSING state.")
        logger.info("This needs to be properly implemented. "
                    "Currently only here for demonstration purposes.")

        seq_num, _, flags, _, _, _ = BTCPSocket.unpack_segment_header(segment[:HEADER_SIZE])

        if flags == fACK:      # only the ACK flag is set
            self.update_state(BTCPStates.CLOSED)
            self._recvbuf.put(bytes(0))
        elif flags == fFIN:    # only the FIN flag is set
            # construct FIN|ACK message
            segment = BTCPSocket.build_segment(seqnum=BTCPSocket.increment(self.packet_handler.current_SN), acknum=seq_num, ack_set=True, fin_set=True, window=self._window)

            # update all constants and values
            self.packet_handler.current_SN = BTCPSocket.increment(self.packet_handler.current_SN)

            self._lossy_layer.send_segment(segment=segment)
            
        elif flags == 0 and not self._fin_received_in_closing and ((seq_num < self.packet_handler.last_received and abs(seq_num - self.packet_handler.last_received) < MAX_DIFF) \
                                                                   or (seq_num > self.packet_handler.last_received and abs(seq_num - self.packet_handler.last_received) > MAX_DIFF)):    # seq_num < pkt_handler.last_rvcd no flags set, and not yet received a FIN
            # construct a ... TODO
            segment = BTCPServerSocket.build_segment(seqnum=BTCPSocket.increment(self.packet_handler.current_SN), acknum=seq_num, ack_set=True, window=self._window)


            # update all constants and values
            self.packet_handler.current_SN = BTCPSocket.increment(self.packet_handler.current_SN)

            self._lossy_layer.send_segment(segment)
        return


    def _syn_segment_received(self, segment):

        logger.debug("_syn_segment_received called")
        logger.info("Segment received in %s state",
                    self._state)

        seq_num, _, flags, _, _, _ = BTCPSocket.unpack_segment_header(segment[:HEADER_SIZE])

        if flags == fACK: # Only the ACK flag is set
            self.packet_handler.last_received = seq_num
            self.update_state(BTCPStates.ESTABLISHED)

        elif flags == fSYN and seq_num == self.sender_SN: # Only the SYN flag is set and it is the same SYN as send at the CONNECTING state
            # construct a segment with the SYN ACK flags set to acknowledge this SYN segment
            segment = BTCPSocket.build_segment(seqnum=self._ISN, acknum=BTCPSocket.increment(seq_num), syn_set=True, ack_set=True, window=self._window)
            self._lossy_layer.send_segment(segment)
        
        elif flags == 0: # in syn rcvd, so not yet established, but we are already recvng data
            segment = BTCPSocket.build_segment(seqnum=self._ISN, acknum=BTCPSocket.increment(self._ISN_sender), syn_set=True, ack_set=True, window=self._window)
            self._lossy_layer.send_segment(segment)

    def _established_segment_received(self, segment):


        seq_num, ack_num, flags, window, data_len, checksum = BTCPSocket.unpack_segment_header(segment[:HEADER_SIZE])

        if flags == 0:  # no flags
            data = self.packet_handler.handle_rcvd_seg(segment)
            print("server: got the data")
            if data:
                self._recvbuf.put(data)

        elif flags == fFIN and seq_num == BTCPSocket.increment(self.packet_handler.last_received):  # Only the FIN flag set and it is in-order
            # construct a segment with FIN ACK flags, we choose to increment SN by 1 and send the SN of the sender back as the ACK.
            # This is an abitrary choice only consistency is important.
            segment = BTCPSocket.build_segment(seqnum=BTCPSocket.increment(self.packet_handler.current_SN), acknum=seq_num, ack_set=True, fin_set=True, window=self._window)
            # update all constants and values
            self.packet_handler.current_SN = BTCPSocket.increment(self.packet_handler.current_SN)
            self._lossy_layer.send_segment(segment)
            self.update_state(BTCPStates.CLOSING)

        return # TODO: PLEZ overal last received incrementen. zenk you.


    def lossy_layer_tick(self):
        logger.debug("lossy_layer_tick called")

        match self._state:
            case BTCPStates.ACCEPTING:
                if self._accept_tries < MAX_TRIES:
                    #FIXME: we need to keep track of whether we want to go back to closed so fast
                    pass
                else:
                    self.update_state(BTCPStates.CLOSED)

            case BTCPStates.SYN_RCVD:
                if self._SYN_tries > MAX_TRIES:
                    self._SYN_tries= 0
                    self.update_state(BTCPStates.ACCEPTING)
                else:
                    segment = BTCPSocket.build_segment(seqnum=self._ISN, acknum=BTCPSocket.increment(self.sender_SN), syn_set=True, ack_set=True, window=self._window)
                    # update all constants and values
                    self._SYN_tries += 1
                    self._lossy_layer.send_segment(segment)
                    
            case BTCPStates.ESTABLISHED:
                # When the server has not recieved something for a while the server will assume
                # nothing has been send for a while or is still in flight. This means it can just wait
                # for while. Thus we do nothing
                pass

            case BTCPStates.CLOSING:
                self.update_state(BTCPStates.CLOSED)

            case BTCPStates.CLOSED:
                # self.timer.stop()
                self._recvbuf.put(bytes(0))


    def accept(self):
        logger.debug("accept called")

        if self._state != BTCPStates.CLOSED:
            logger.debug(f"accept was called, but the server was not in the CLOSED state. Server is in {self._state} instead")
            logger.debug("accept performed.")
        
        self._state = BTCPStates.ACCEPTING
        self._ISN = self.reset_ISN()
        self.packet_handler = GBN(window_size=self._window, lossy_layer=self._lossy_layer, ISN=self._ISN)
        while self._state != BTCPStates.CLOSED and self._state != BTCPStates.ESTABLISHED:
            time.sleep(0.1)

        logger.debug("accept performed.")


    def recv(self):
        logger.debug("recv called")

        data = bytearray()
        logger.info("Retrieving data from receive queue")
        try:
            # Wait until one segment becomes available in the buffer, or
            # timeout signalling disconnect.
            logger.info("Blocking get for first chunk of data.")
            data.extend(self._recvbuf.get(block=True, timeout=30))
            logger.debug("First chunk of data retrieved.")
            logger.debug("Looping over rest of queue.")
            while True:
                # Empty the rest of the buffer, until queue.Empty exception
                # exits the loop. If that happens, data contains received
                # segments so that will *not* signal disconnect.
                data.extend(self._recvbuf.get_nowait())
                logger.debug("Additional chunk of data retrieved.")
        except queue.Empty:
            logger.debug("Queue emptied or timeout reached")
            pass # (Not break: the exception itself has exited the loop)
        if not data:
            logger.info("No data received for 30 seconds.")
            logger.info("Returning empty bytes to caller, signalling disconnect.")
        data = bytes(data)
        return data


    def close(self):
        logger.debug("close called")
        if self._lossy_layer is not None:
            self._lossy_layer.destroy()
        self._lossy_layer = None


    def __del__(self):
        """Destructor. Do not modify."""
        logger.debug("__del__ called")
        self.close()
