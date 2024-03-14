from btcp.btcp_socket import BTCPSocket, BTCPStates, BTCPSignals
from btcp.lossy_layer import LossyLayer
from btcp.constants import *
from btcp.GBN import GBN

import queue
import time
import struct
import logging


logger = logging.getLogger(__name__)


class BTCPServerSocket(BTCPSocket):
    """bTCP server socket
    A server application makes use of the services provided by bTCP by calling
    accept, recv, and close.

    You're implementing the transport layer, exposing it to the application
    layer as a (variation on) socket API. Do note, however, that this socket
    as presented is *always* in "listening" state, and handles the client's
    connection in the same socket. You do not have to implement a separate
    listen socket. If you get everything working, you may do so for some extra
    credit.

    To implement the transport layer, you also need to interface with the
    network (lossy) layer. This happens by both calling into it
    (LossyLayer.send_segment) and providing callbacks for it
    (BTCPServerSocket.lossy_layer_segment_received, lossy_layer_tick).

    Your implementation will operate in two threads, the network thread,
    where the lossy layer "lives" and where your callbacks will be called from,
    and the application thread, where the application calls connect, send, etc.
    This means you will need some thread-safe information passing between
    network thread and application thread.
    Writing a boolean or enum attribute in one thread and reading it in a loop
    in another thread should be sufficient to signal state changes.
    Lists, however, are not thread safe, so to pass data and segments around
    you probably want to use Queues, or a similar thread safe collection.
    """


    def __init__(self, window, timeout):
        """Constructor for the bTCP server socket. Allocates local resources
        and starts an instance of the Lossy Layer.

        You can extend this method if you need additional attributes to be
        initialized, but do *not* call accept from here.
        """
        logger.debug("__init__() called.")
        super().__init__(window, timeout)
        self._lossy_layer = LossyLayer(self, SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT)
        self.packet_handler = GBN(window_size=window, ISN=0) # TODO: change ISN in negotiation.

        # The data buffer used by lossy_layer_segment_received to move data
        # from the network thread into the application thread. Bounded in size.
        # If data overflows the buffer it will get lost -- that's what window
        # size negotiation should solve.
        # For this rudimentary implementation, we simply hope receive manages
        # to be faster than send.
        self._recvbuf = queue.Queue(maxsize=1000)
        self._fin_received_in_closing = False
        logger.info("Socket initialized with recvbuf size 1000")

        # Make sure the example timer exists from the start.
        self._example_timer = None

        # Number of tries to establish
        self._SYN_tries = 0
        self._MAX_SYN_TRIES = 10



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
        """Called by the lossy layer whenever a segment arrives.

        Things you should expect to handle here (or in helper methods called
        from here):
            - checksum verification (and deciding what to do if it fails)
            - receiving syn and client's ack during handshake
            - receiving segments and sending acknowledgements for them,
              making data from those segments available to application layer
            - receiving fin and client's ack during termination
            - any other handling of the header received from the client

        Remember, we expect you to implement this *as a state machine!*
        You have quite a bit of freedom in how you do this, but we at least
        expect you to *keep track of the state the protocol is in*,
        *perform the appropriate state transitions based on events*, and
        *alter behaviour based on that state*.

        So when you receive the segment, do the processing that is common
        for all states (verifying the checksum, parsing it into header values
        and data...).
        Then check the protocol state, do appropriate state-based processing
        (e.g. a FIN is not an acceptable segment in ACCEPTING state, whereas a
        SYN is).
        Finally, do post-processing that is common to all states.

        You could e.g. implement the state-specific processing in a helper
        function per state, and simply call the appropriate helper function
        based on which state you are in.
        In that case, it will be very helpful to split your processing into
        smaller helper functions, that you can combine as needed into a larger
        function for each state.

        If you are on Python 3.10, feel free to use the match ... case
        statement.
        If you are on an earlier Python version, an if ... elif ...  elif
        construction can be used; just make sure to check the same variable in
        each elif.
        """
        logger.debug("lossy_layer_segment_received called")
        logger.debug(segment)

        if not len(segment) == SEGMENT_SIZE:
            raise NotImplementedError("Segment not long enough handle not implemented")
        else:
            header, data = segment[:HEADER_SIZE], segment[HEADER_SIZE:]
            seq_num, ack_num, flags, window, data_len, checksum = BTCPSocket.unpack_segment_header(header)
            if not BTCPSocket.verify_checksum(header):
                # probably just ignore / drop the packet.
                return
            else:
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


        self._expire_timers()
        return


    def _accepting_segment_received(self, segment):
        """
        This function will handle incomming segments when in the accepting state. Meaning:
        if a SYN -> send a SYN|ACK
        else ignore all
        """

        logger.info("accepting a segment")
        logger.debug(segment)

        seq_num, ack_num, flags, window, data_len, checksum = BTCPSocket.unpack_segment_header(segment[:HEADER_SIZE])
        # Slice data from incoming segment.


        # If the segment has a SYN flag we reply with a SYN|ACK to start a connection
        if flags & fSYN:  # SYN flag is set
            # update variables consistent with handshake
            self.update_state(BTCPStates.SYN_RCVD)
            self.sender_SN = seq_num
            self.packet_handler.current_SN += 1

            # construct segment
            pseudo_header = BTCPSocket.build_segment_header(seqnum=self._ISN, acknum=seq_num+1, syn_set=True, ack_set=True, window=self._window)
            header = BTCPSocket.build_segment_header(seqnum=self._ISN, acknum=seq_num+1, syn_set=True, ack_set=True, checksum=BTCPSocket.in_cksum(pseudo_header))
            segment = header + bytes(PAYLOAD_SIZE)

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

        seq_num, ack_num, flags, window, data_len, checksum = BTCPSocket.unpack_segment_header(segment[:HEADER_SIZE])

        if flags == fACK:      # only the ACK flag is set
            self.update_state(BTCPStates.CLOSED)
        elif flags == fFIN:    # only the FIN flag is set
            # construct FIN|ACK message
            pseudo_header = BTCPSocket.build_segment_header(seqnum=self.packet_handler.current_SN+1, acknum=seq_num, ack_set=True, fin_set=True)  #TODO: SCHRIJF COMMENTS PLEZ
            header = BTCPSocket.build_segment_header(seqnum=self.packet_handler.current_SN+1, acknum=seq_num, ack_set=True, fin_set=True, checksum=BTCPSocket.in_cksum(pseudo_header))
            segment = header + bytes(PAYLOAD_SIZE)

            # update all constants and values
            self.packet_handler.current_SN += 1

            self._lossy_layer.send_segment(segment=segment)
            
        elif flags == 0 and not self._fin_received_in_closing and seq_num < self.packet_handler.last_received:    # no flags set, and not yet received a FIN
            # construct a ... TODO
            pseudo_header = BTCPSocket.build_segment_header(seqnum=self.packet_handler.current_SN+1, acknum=seq_num, ack_set=True)
            header = BTCPSocket.build_segment_header(seqnum=self.packet_handler.current_SN+1, acknum=seq_num, ack_set=True, checksum=BTCPSocket.in_cksum(pseudo_header))
            segment = header + bytes(PAYLOAD_SIZE)

            # update all constants and values
            self.packet_handler.current_SN += 1

            self._lossy_layer.send_segment(segment)
        return


    def _syn_segment_received(self, segment):
        """
        This function handles all segments recieved when in the SYN state.
        """
        logger.debug("_syn_segment_received called")
        logger.info("Segment received in %s state",
                    self._state)

        seq_num, ack_num, flags, window, data_len, checksum = BTCPSocket.unpack_segment_header(segment[:HEADER_SIZE])

        if flags == fACK: # Only the ACK flag is set
            self.update_state(BTCPStates.ESTABLISHED)
        elif flags == fSYN and seq_num == self.sender_SN: # Only the SYN flag is set and it is the same SYN as send at the CONNECTING state
            # construct a segment with the SYN ACK flags set to acknowledge this SYN segment
            pseudo_header = BTCPSocket.build_segment_header(seqnum=self._ISN, acknum=seq_num+1, syn_set=True, ack_set=True, window=self._window)
            header = BTCPSocket.build_segment_header(seqnum=self._ISN, acknum=seq_num+1, syn_set=True, ack_set=True, checksum=BTCPSocket.in_cksum(pseudo_header))
            segment = header + bytes(PAYLOAD_SIZE)

            # update all constants and values
            self.packet_handler.current_SN += 1

            self._lossy_layer.send_segment(segment)
        
    def _established_segment_received(self, segment):
        seq_num, ack_num, flags, window, data_len, checksum = BTCPSocket.unpack_segment_header(segment[:HEADER_SIZE])
        
        if flags == 0:  # no flags
            self.packet_handler.handle_rcvd_seg(segment)
        elif flags == fFIN and seq_num == self.packet_handler.last_received + 1:  # Only the FIN flag set and it is in-order
            # construct a segment with FIN ACK flags, we choose to increment SN by 1 and send the SN of the sender back as the ACK.
            # This is an abitrary choice only consistency is important.
            pseudo_header = BTCPSocket.build_segment_header(self.packet_handler.current_SN+1, acknum=seq_num, ack_set=True, fin_set=True)
            header = BTCPSocket.build_segment_header(self.packet_handler.current_SN+1, acknum=seq_num, ack_set=True, fin_set=True, checksum=BTCPSocket.in_cksum(pseudo_header))
            segment = header + bytes(PAYLOAD_SIZE)
            
            # update all constants and values
            self.packet_handler.current_SN += 1

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
        self._start_example_timer()
        self._expire_timers()

        match self._state:
            case BTCPStates.ACCEPTING:
                self.update_state(BTCPStates.CLOSED)
            case BTCPStates.SYN_RCVD:
                if self._SYN_tries > self._MAX_SYN_TRIES:
                    self._SYN_TRIES = 0
                    self.update_state(BTCPStates.ACCEPTING)
                else:
                    # construct a reply segment with ... TODO
                    pseudo_header = BTCPSocket.build_segment_header(seqnum=self._ISN, acknum=self.sender_SN+1, syn_set=True, ack_set=True, window=self._window)
                    header = BTCPSocket.build_segment_header(seqnum=self._ISN, acknum=self.sender_SN+1, syn_set=True, ack_set=True, checksum=BTCPSocket.in_cksum(pseudo_header))
                    segment = header + bytes(PAYLOAD_SIZE)
                    
                    # update all constants and values
                    self._SYN_tries += 1
                    self.update_state(BTCPStates.SYN_RCVD)

                    self._lossy_layer.send_segment(segment)
            case BTCPStates.ESTABLISHED:
                # When the server has not recieved something for a while the server will assume
                # nothing has been send for a while or is still in flight. This means it can just wait
                # for while. Thus we do nothing
                pass
            case BTCPStates.CLOSING:
                self.update_state(BTCPStates.CLOSED)

    # The following two functions show you how you could implement a (fairly
    # inaccurate) but easy-to-use timer.
    # You *do* have to call _expire_timers() from *both* lossy_layer_tick
    # and lossy_layer_segment_received, for reasons explained in
    # lossy_layer_tick. TODO TODO
    def _start_example_timer(self):
        if not self._example_timer:
            logger.debug("Starting example timer.")
            # Time in *nano*seconds, not milli- or microseconds.
            # Using a monotonic clock ensures independence of weird stuff
            # like leap seconds and timezone changes.
            self._example_timer = time.monotonic_ns()
        else:
            logger.debug("Example timer already running.")


    def _expire_timers(self):
        curtime = time.monotonic_ns()
        if not self._example_timer:
            logger.debug("Example timer not running.")
        elif curtime - self._example_timer > self._timeout * 1_000_000:
            logger.debug("Example timer elapsed.")
            self._example_timer = None
        else:
            logger.debug("Example timer not yet elapsed.")


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
        
        self._start_example_timer()
        self._state = BTCPStates.ACCEPTING
        self._ISN = self.reset_ISN()
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
        in_order_data = bytearray()
        for segment in data:
            in_order_data.extend(self.packet_handler.handle_rcvd_seg(segment))
        return bytes(in_order_data)


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
