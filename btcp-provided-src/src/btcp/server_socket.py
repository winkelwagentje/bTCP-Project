from btcp.btcp_socket import BTCPSocket, BTCPStates, BTCPSignals
from btcp.lossy_layer import LossyLayer
from btcp.constants import *
from btcp.GBN import GBN
from btcp.resettable_timer import ResettableTimer
import inspect

import queue
import time
import struct
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


    ###########################################################################
    ### The following section is the interface between the transport layer  ###
    ### and the lossy (network) layer. When a segment arrives, the lossy    ###
    ### layer will call the lossy_layer_segment_received method "from the   ###
    ### network thread". In that method you should handle the checking of   ###
    ### the segment, and take other actions that should be taken upon its   ###
    ### arrival, like acknowledging the segment and making the data         ###
    ### available for the application thread that calls to recv can return  ###
    ### the data.                                                           ###
    ###                                                                     ###
    ### Of course you can implement this using any helper methods you want  ###
    ### to add.                                                             ###
    ###                                                                     ###
    ### Since the implementation is inherently multi-threaded, you should   ###
    ### use a Queue, not a List, to transfer the data to the application    ###
    ### layer thread: Queues are inherently threadsafe, Lists are not.      ###
    ###########################################################################

    def lossy_layer_segment_received(self, segment):
        logger.debug("lossy_layer_segment_received called")
        logger.debug(segment)
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
        logger.debug(segment)

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
        """
        Helper method handling received segment in CLOSING state
        """

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
        """
        This function handles all segments recieved when in the SYN state.
        """

        logger.debug("_syn_segment_received called")
        logger.info("Segment received in %s state",
                    self._state)

        seq_num, _, flags, _, _, _ = BTCPSocket.unpack_segment_header(segment[:HEADER_SIZE])

        if flags == fACK: # Only the ACK flag is set
            # self.timer.stop()  # no timer needed in ESTABLISHED handled by packet_handler
            # TODO: THE FOLLOWING LINE IS WEIRD IMO AS AGAIN, WE ARE DEALING AN ACK
            # I THINK THE SEQ NUM OF A ACK SEGMENT IS IRRELEVANT
            self.packet_handler.last_received = seq_num
            self.update_state(BTCPStates.ESTABLISHED)

        elif flags == fSYN and seq_num == self.sender_SN: # Only the SYN flag is set and it is the same SYN as send at the CONNECTING state
            # construct a segment with the SYN ACK flags set to acknowledge this SYN segment
            segment = BTCPSocket.build_segment(seqnum=self._ISN, acknum=BTCPSocket.increment(seq_num), syn_set=True, ack_set=True, window=self._window)

            # update all constants and values
            self.packet_handler.current_SN = BTCPSocket.increment(self.packet_handler.current_SN)

            self._lossy_layer.send_segment(segment)
        
        elif flags == 0: # in syn rcvd, so not yet established, but we are already recvng data
            segment = BTCPSocket.build_segment(seqnum=self._ISN, acknum=BTCPSocket.increment(self._ISN_sender), syn_set=True, ack_set=True, window=self._window)
            self._lossy_layer.send_segment(segment)

    def _established_segment_received(self, segment):


        seq_num, ack_num, flags, window, data_len, checksum = BTCPSocket.unpack_segment_header(segment[:HEADER_SIZE])

        if flags == 0:  # no flags
            data = self.packet_handler.handle_rcvd_seg(segment)
            if data:
                self._recvbuf.put(data)
        elif flags == fFIN and seq_num == (self.packet_handler.last_received + 1) % MAX_INT:  # Only the FIN flag set and it is in-order
            # construct a segment with FIN ACK flags, we choose to increment SN by 1 and send the SN of the sender back as the ACK.
            # This is an abitrary choice only consistency is important.
            segment = BTCPSocket.build_segment(seqnum=BTCPSocket.increment(self.packet_handler.current_SN), acknum=seq_num, ack_set=True, fin_set=True, window=self._window)
            
            # update all constants and values
            self.packet_handler.current_SN = BTCPSocket.increment(self.packet_handler.current_SN)

            self._lossy_layer.send_segment(segment)

            self.update_state(BTCPStates.CLOSING)

        return # TODO: PLEZ overal last received incrementen. zenk you.


    def lossy_layer_tick(self):
        """Called by the lossy layer whenever no segment has arrived for
        TIMER_TICK milliseconds. Defaults to 100ms, can be set in constants.py.

        NOTE: Will NOT be called if segments are arriving; do not rely on
        simply counting calls to this method for an accurate timeout. If 10
        segments arrive, each 99 ms apart, this method will NOT be called for
        over a second!

        The primary use for this method is to be able to do things in the
        "network thread" even while no segments are arriving -- which would
        otherwise trigger a call to lossy_layer_segment_received. On the server
        side, you may find you have no actual need for this method. Or maybe
        you do. See if it suits your implementation.

        You will probably see some code duplication of code that doesn't handle
        the incoming segment among lossy_layer_segment_received and
        lossy_layer_tick. That kind of duplicated code would be a good
        candidate to put in a helper method which can be called from either
        lossy_layer_segment_received or lossy_layer_tick.
        """
        logger.debug("lossy_layer_tick called")
        # self._start_example_timer()TODO
        # self._expire_timers()

        if self._state != BTCPStates.CLOSED:
            # self.timer.reset()
            pass

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
                    # construct a reply segment with ... TODO
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


    ###########################################################################
    ### You're also building the socket API for the applications to use.    ###
    ### The following section is the interface between the application      ###
    ### layer and the transport layer. Applications call these methods to   ###
    ### accept connections, receive data, etc. Conceptually, this happens   ###
    ### in "the application thread".                                        ###
    ###                                                                     ###
    ### You *can*, from this application thread, send segments into the     ###
    ### lossy layer, i.e. you can call LossyLayer.send_segment(segment)     ###
    ### from these methods without ensuring that happens in the network     ###
    ### thread. However, if you do want to do this from the network thread, ###
    ### you should use the lossy_layer_tick() method above to ensure that   ###
    ### segments can be sent out even if no segments arrive to trigger the  ###
    ### call to lossy_layer_segment_received. When passing segments between ###
    ### the application thread and the network thread, remember to use a    ###
    ### Queue for its inherent thread safety. Whether you need to send      ###
    ### segments from the application thread into the lossy layer is up to  ###
    ### you; you may find you can handle all receiving *and* sending of     ###
    ### segments in the lossy_layer_segment_received and lossy_layer_tick   ###
    ### methods.                                                            ###
    ###                                                                     ###
    ### Note that because this is the server socket, and our (initial)      ###
    ### implementation of bTCP is one-way reliable data transfer, there is  ###
    ### no send() method available to the applications. You should still    ###
    ### be able to send segments on the lossy layer, however, because       ###
    ### of acknowledgements and synchronization. You should implement that  ###
    ### above.                                                              ###
    ###########################################################################

    def accept(self):
        """Accept and perform the bTCP three-way handshake to establish a
        connection.

        accept should *block* (i.e. not return) until a connection has been
        successfully established (or some timeout is reached, if you want. Feel
        free to add a timeout to the arguments). You will need some
        coordination between the application thread and the network thread for
        this, because the syn and final ack from the client will be received in
        the network thread.

        Hint: assigning to a boolean or enum attribute in thread A and reading
        it in a loop in thread B (preferably with a short sleep to avoid
        wasting a lot of CPU time) ensures that thread B will wait until the
        boolean or enum has the expected value. You can also put some kind of
        "signal" (e.g. BTCPSignals.CONNECT, or BTCPStates.FIN_SENT) in a Queue,
        and use a blocking get() on the other side to receive that signal.

        We do not think you will need more advanced thread synchronization in
        this project.
        """
        logger.debug("accept called")

        if self._state != BTCPStates.CLOSED:
            logger.debug(f"accept was called, but the server was not in the CLOSED state. Server is in {self._state} instead")
            logger.debug("accept performed.")
        
        # self.timer.reset()  # start timer
        self._state = BTCPStates.ACCEPTING
        self._ISN = self.reset_ISN()
        self.packet_handler = GBN(window_size=self._window, lossy_layer=self._lossy_layer, ISN=self._ISN)
        while self._state != BTCPStates.CLOSED and self._state != BTCPStates.ESTABLISHED:
            time.sleep(0.1)

        logger.debug("accept performed.")


    def recv(self):
        """Return data that was received from the client to the application in
        a reliable way.

        If no data is available to return to the application, this method
        should block waiting for more data to arrive. If the connection has
        been terminated, this method should return with no data (e.g. an empty
        bytes b'').

        If you want, you can add an argument to this method stating how many
        bytes you want to receive in one go at the most (but this is not
        required for this project).

        You are free to implement this however you like, but the following
        explanation may help to understand how sockets *usually* behave and you
        may choose to follow this concept as well:

        The way this usually works is that "recv" operates on a "receive
        buffer". Once data has been successfully received and acknowledged by
        the transport layer, it is put "in the receive buffer". A call to recv
        will simply return data already in the receive buffer to the
        application.  If no data is available at all, the method will block
        until at least *some* data can be returned.
        The actual receiving of the data, i.e. reading the segments, sending
        acknowledgements for them, reordering them, etc., happens *outside* of
        the recv method (e.g. in the network thread).
        Because of this blocking behaviour, an *empty* result from recv signals
        that the connection has been terminated.

        Again, you should feel free to deviate from how this usually works.
        """
        logger.debug("recv called")

        # Rudimentary example implementation:
        # Empty the queue in a loop, reading into a larger bytearray object.
        # Once empty, return the data as bytes.
        # If no data is received for 30 seconds, a disconnect is assumed.
        # At that point recv returns no data and thereby signals disconnect
        # to the server application.
        # Proper handling should use the bTCP state machine to check that the
        # client has disconnected when a timeout happens, and keep blocking
        # until data has actually been received if it's still possible for
        # data to appear.
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
        logger.debug(data)
        if not data:
            logger.info("No data received for 30 seconds.")
            logger.info("Returning empty bytes to caller, signalling disconnect.")
        data = bytes(data)
        return data


    def close(self):
        """Cleans up any internal state by at least destroying the instance of
        the lossy layer in use. Also called by the destructor of this socket.

        Do not confuse with shutdown, which disconnects the connection.
        close destroys *local* resources, and should only be called *after*
        shutdown.

        Probably does not need to be modified, but if you do, be careful to
        gate all calls to destroy resources with checks that destruction is
        valid at this point -- this method will also be called by the
        destructor itself. The easiest way of doing this is shown by the
        existing code:
            1. check whether the reference to the resource is not None.
                2. if so, destroy the resource.
            3. set the reference to None.
        """
        logger.debug("close called")
        if self._lossy_layer is not None:
            self._lossy_layer.destroy()
        self._lossy_layer = None


    def __del__(self):
        """Destructor. Do not modify."""
        logger.debug("__del__ called")
        self.close()
