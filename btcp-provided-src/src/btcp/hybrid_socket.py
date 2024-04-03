from btcp.btcp_socket import BTCPSocket, BTCPStates
from btcp.lossy_layer import LossyLayer
from btcp.constants import *
from btcp.GBN import GBN
from btcp.SR import SR

import time
import queue
import logging


logger = logging.getLogger(__name__)


class BTCPHybridSocket(BTCPSocket):
    def __init__(self, window, timeout, source_ip, source_port, dest_ip, dest_port):
        logger.debug("__init__ called")
        
        self.packet_handler = None
        super().__init__(window, timeout)
        self._lossy_layer = LossyLayer(self, source_ip, source_port, dest_ip, dest_port)

        self._sendbuf = queue.Queue(maxsize=1000)  # NOTE gebruiken
        self._recvbuf = queue.Queue(maxsize=1000)
        self._fin_received_in_closing = False

        # initialize a number of timeout counters
        self._SYN_sent_tries = 0
        self._SYN_rcvd_tries = 0
        self._FIN_tries = 0
        self._accept_tries = 0

    def lossy_layer_segment_received(self, segment):
        """
        If data has been received by the lossy layer all segments will be sent to this function.
        This function will verify that the segment is not corrupted and of correct length before
        passing it on to the appropriate function depending on the current state of the socket.
        """
        logger.info("self.lossy_layer_segment_received() is called")

        if len(segment) == SEGMENT_SIZE and BTCPSocket.verify_checksum(segment):
            # segment is not corrupted and may be passed on. 
            match self._state: 
                case BTCPStates.SYN_SENT:
                    self._syn_sent_segment_received(segment)
                case BTCPStates.ESTABLISHED:
                    self._established_segment_received(segment)
                case BTCPStates.FIN_SENT:
                    self._fin_sent_segment_received(segment)
                case BTCPStates.ACCEPTING: 
                    self._accepting_segment_received(segment)
                case BTCPStates.CLOSING: 
                    self._closing_segment_received(segment)
                case BTCPStates.SYN_RCVD:
                    self._syn_rcvd_segment_received(segment)
        else:
            logger.debug("a received segment was corrupted or of incorrect length")
        return 


    def _syn_sent_segment_received(self, segment):
        """
        recv SYN|ACK -> send ACK
        client_socket function 
        """
        seq_num, ack_num, flags, window, _, _ = BTCPSocket.unpack_segment_header(segment[:HEADER_SIZE])
        if flags == fSYN+fACK and ack_num == BTCPSocket.increment(self._ISN): # check iff syn and ack flags are set, and if the ack is the expected ack. self.packet_handler.window_size = window
            self.packet_handler.window_size = window
            segment = BTCPSocket.build_segment(seqnum=ack_num, acknum=BTCPSocket.increment(seq_num), ack_set=True, window=self._window)
            self._lossy_layer.send_segment(segment)

            self._ISN_sender = seq_num  # setting sender ISN

            logger.warning("going to established")
            self.update_state(BTCPStates.ESTABLISHED)


    def _established_segment_received(self, segment):
        """
        This function handles segments received while in the ESTABLISHED state.
        If a segment has no flags it contains data, which means we will pass the segment to the pakket handler.
        The packethandler might return data, which we can assume is in-order and as such we put it on the recv buffer.
        If the segment has the FIN flag, and is in-order, we send a FIN|ACK and move to the CLOSING state.
        """
        logger.info("self._established_segment_received() called")

        seq_num, ack_num, flags, _, _, _ = BTCPSocket.unpack_segment_header(segment[:HEADER_SIZE])
        if flags == 0:  # no flags, so a segment containing data
            logger.debug("segment received contains data and will be passed to the packet handler.")
            data = self.packet_handler.handle_rcvd_seg(segment)
            
            # update the window size
            self.packet_handler.window_size = max(1, min(self.packet_handler.window_size, self._recvbuf.maxsize - self._recvbuf.qsize()))
            
            if data:
                # if data is not empty then we put it on the receive buffer, 
                # otherwise b'' or None is put on the rcv buffer which might end the recv function prematurely.
                self._recvbuf.put(data)

        elif flags == fACK:
            self.packet_handler.handle_rcvd_seg(segment)
        elif flags == fSYN + fACK and ack_num == BTCPSocket.increment(self._ISN):
                segment = BTCPSocket.build_segment(seqnum=ack_num, acknum=BTCPSocket.increment(seq_num), ack_set=True, window=self._window)
                self._lossy_layer.send_segment(segment)
        elif flags == fFIN and seq_num == BTCPSocket.increment(self.packet_handler.last_received):  # Only the FIN flag set and it is in-order
            logger.debug("segment received was an in-order FIN. Sending a FIN|ACK and moving to the CLOSING state.")
            # sending a segment with FIN ACK flags, we choose to increment SN by 1 and send the SN of the sender back as the ACK.
            # This is an abitrary choice only consistency is important.
            segment = BTCPSocket.build_segment(seqnum=BTCPSocket.increment(self.packet_handler.current_SN), acknum=seq_num, ack_set=True, fin_set=True, window=self._window)
            
            self.packet_handler.current_SN = BTCPSocket.increment(self.packet_handler.current_SN)
            self._lossy_layer.send_segment(segment)
            
            self.update_state(BTCPStates.CLOSING)
    

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


    def _accepting_segment_received(self, segment):
        """
        This function handles segments received when in the accepting state. 
        If the segment has the SYN flag a SYN|ACK with ACK=rcvd_syn + 1 and SYN = ISN. 
        """
        logger.info("self._accepting_segment_received has been called")

        seq_num, _, flags, window, _, _ = BTCPSocket.unpack_segment_header(segment[:HEADER_SIZE])
        
        # If the segment has a SYN flag we reply with a SYN|ACK to start a connection
        if flags & fSYN:  # SYN flag is set
            logger.debug("received segment in accepting state has the SYN flag. Sending a SYN|ACK..")
            self.update_state(BTCPStates.SYN_RCVD)

            # update variables consistent with handshake
            self.sender_SN = seq_num
            self._ISN_sender = seq_num 
            self.packet_handler.current_SN = BTCPSocket.increment(self.packet_handler.current_SN)
            self.packet_handler.last_received = seq_num

            # construct segment
            self._window = max(1, min(self._window, window))
            segment = BTCPSocket.build_segment(seqnum=self._ISN, acknum=BTCPSocket.increment(seq_num),syn_set=True, ack_set=True, window=self._window)
            self._lossy_layer.send_segment(segment)
        return


    def _closing_segment_received(self, segment):
        """
        This function handles segments received when in the closing state.
        If the segment is an ACK (in-order) we move to the CLOSED state.
        If the segment is a FIN we resend a FIN|ACK.
        If the segment is a retransmitted segment we send an ACK.
        """

        logger.info("_closing_segment_received called")

        seq_num, _, flags, _, _, _ = BTCPSocket.unpack_segment_header(segment[:HEADER_SIZE])

        if flags == fACK:  # only the ACK flag is set
            logger.debug("received segment has the ACK flag set. Moving to the CLOSED state.")

            self.update_state(BTCPStates.CLOSED)
            self._recvbuf.put(bytes(0))  # put b'' on the recvbuf incase it is empty, so the recv function will terminate

        elif flags == fFIN:    # only the FIN flag is set
            logger.debug("received segment has the FIN flag set. Resending a FIN|ACK.")
            # sending FIN|ACK message
            segment = BTCPSocket.build_segment(seqnum=BTCPSocket.increment(self.packet_handler.current_SN), acknum=seq_num, ack_set=True, fin_set=True, window=self._window)

            self.packet_handler.current_SN = BTCPSocket.increment(self.packet_handler.current_SN)
            self._lossy_layer.send_segment(segment=segment)

        elif flags == 0 and not self._fin_received_in_closing and BTCPSocket.lt(seq_num, self.packet_handler.last_received):  # seq_num < pkt_handler.last_rvcd no flags set, and not yet received a FIN
            # the segments has no flags, no prior fins have been received and the SN < last received SN, so this is a retransmitted segment.
            logger.debug("received segment was a retransmitted segment")
            # sending an ACK
            segment = BTCPSocket.build_segment(seqnum=BTCPSocket.increment(self.packet_handler.current_SN), acknum=seq_num, ack_set=True, window=self._window)

            self.packet_handler.current_SN = BTCPSocket.increment(self.packet_handler.current_SN)
            self._lossy_layer.send_segment(segment)
        return


    def _syn_rcvd_segment_received(self, segment):
        """
        (originally server socket function)
        This functions handles segments received when in the SYN_RCVD state.
        If the segment has the ACK flag set we move to the ESTABLISHED state.
        If the segment has the SYN flag set we retransmit a SYN|ACK.
        If the segment has no flags, so it contains data, we retransmit a SYN|ACK.
        """
        logger.info("_syn_rcvd_segment_received called")

        seq_num, _, flags, _, _, _ = BTCPSocket.unpack_segment_header(segment[:HEADER_SIZE])

        if flags == fACK:  # Only the ACK flag is set
            logger.debug("received segment was an ACK. Moving to the ESTABLISHED state.")

            self.packet_handler.last_received = seq_num
            self.update_state(BTCPStates.ESTABLISHED)

        elif flags == fSYN and seq_num == self.sender_SN:  # Only the SYN flag is set and it is the same SYN as received in the CONNECTING state
            logger.debug("received segment was a SYN. Retransmitting a SYN|ACK")
            # sending a segment with the SYN|ACK flags set to acknowledge this SYN segment
            segment = BTCPSocket.build_segment(seqnum=self._ISN, acknum=BTCPSocket.increment(seq_num), syn_set=True, ack_set=True, window=self._window)
            self._lossy_layer.send_segment(segment)
        
        elif flags == 0:  # segment received was data, so we resend SYN|ACK
            logger.debug("received segment is a data segment. Resending a SYN|ACK.")
            segment = BTCPSocket.build_segment(seqnum=self._ISN, acknum=BTCPSocket.increment(self._ISN_sender), syn_set=True, ack_set=True, window=self._window)
            self._lossy_layer.send_segment(segment)


    def lossy_layer_tick(self):
        """
        Called by the lossy layer whenever no segment has arrived for
        TIMER_TICK milliseconds. Defaults to 100ms, can be set in constants.py.
        """
        logger.info(f"self.lossy_layer_tick() called in state {self._state}")

        match self._state:
            case BTCPStates.ACCEPTING:
                if self._accept_tries < MAX_TRIES:
                    self._accept_tries += 1  # NOTE test this if work remove line under here
                    #FIXME: we need to keep track of whether we want to go back to closed so fast
                    pass
                else:
                    self.update_state(BTCPStates.CLOSED)

            case BTCPStates.SYN_RCVD:
                if self._SYN_rcvd_tries > MAX_TRIES:
                    self._SYN_rcvd_tries = 0
                    self.update_state(BTCPStates.ACCEPTING)
                else:
                    segment = BTCPSocket.build_segment(seqnum=self._ISN, acknum=BTCPSocket.increment(self.sender_SN), syn_set=True, ack_set=True, window=self._window)
                    # update all constants and values
                    self._SYN_rcvd_tries += 1
                    self._lossy_layer.send_segment(segment)

            case BTCPStates.SYN_SENT:
                if self._SYN_sent_tries > MAX_TRIES:
                    self._SYN_sent_tries = 0
                    self.update_state(BTCPStates.CLOSED)
                else:
                    self._SYN_sent_tries += 1

                    # re-send connecting SYN
                    segment = BTCPSocket.build_segment(seqnum=self._ISN, acknum=0, syn_set=True, window=self._window)
                    self._lossy_layer.send_segment(segment)
                    
            case BTCPStates.ESTABLISHED:
                # When the server has not recieved something for a while the server will assume
                # nothing has been send for a while or is still in flight. This means it can just wait
                # for while. Thus we do nothing  TODO outdated
                pass

            case BTCPStates.FIN_SENT:
                if self._FIN_tries > MAX_TRIES:
                    self._FIN_tries = 0
                    self.update_state(BTCPStates.CLOSED)
                else:
                    self._FIN_tries += 1
                    segment = BTCPSocket.build_segment(seqnum=self.packet_handler.current_SN, acknum=0, fin_set=True, window=self._window)
                    self._lossy_layer.send_segment(segment)

            case BTCPStates.CLOSING:
                self.update_state(BTCPStates.CLOSED)

            case BTCPStates.CLOSED:
                # self.timer.stop()
                self._recvbuf.put(bytes(0))


    def accept(self):
        logger.debug("accept called")

        if self._state != BTCPStates.CLOSED:
            # not in CLOSED calling accept makes no sense so it is just ignored
            logger.debug(f"accept was called, but the server was not in the CLOSED state. Server is in {self._state} instead")
            logger.debug("accept performed.")
        
        self._state = BTCPStates.ACCEPTING
        self._ISN = self.reset_ISN()
        self.packet_handler = SR(window_size=self._window, lossy_layer=self._lossy_layer, ISN=self._ISN)
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
    

    def connect(self):
        if not self._state == BTCPStates.CLOSED:
            logger.debug("connect was called while not in closed. do nothing.")
            return 
        
        logger.debug("connect called")
                     
        # send 16 bit SNF, set SYN FLAG
        self._ISN = self.reset_ISN()
        segment = BTCPSocket.build_segment(seqnum=self._ISN, acknum=0, syn_set=True, window=self._window)

        self._lossy_layer.send_segment(segment)
        self.update_state(BTCPStates.SYN_SENT)

        self.packet_handler = SR(window_size=self._window, lossy_layer=self._lossy_layer, ISN=self._ISN)
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
            while (not self.packet_handler.expected_ACK_queue.empty()) or (not self.packet_handler.seg_queue.empty()):
                time.sleep(0.1)
            logger.warning("\n"*10 + "WEEOEE")
            #logger.warning(f"{list(self.packet_handler.expected_ACK_queue.queue)}, {list(self.packet_handler.seg_queue.queue)}")

            segment = BTCPSocket.build_segment(seqnum=BTCPSocket.increment(self.packet_handler.current_SN), acknum=0, fin_set=True, window=self._window)
            self._lossy_layer.send_segment(segment)

            self.packet_handler.current_SN = BTCPSocket.increment(self.packet_handler.current_SN)
            self.update_state(BTCPStates.FIN_SENT)

            while not self._state == BTCPStates.CLOSED:
                time.sleep(0.1)


    def close(self):
        logger.debug("close called")
        if self._lossy_layer is not None:
            self._lossy_layer.destroy()
        self._lossy_layer = None


    def __del__(self):
        """Destructor. Do not modify."""
        logger.debug("__del__ called")
        self.close()
