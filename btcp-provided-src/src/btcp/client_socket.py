from btcp.btcp_socket import BTCPSocket, BTCPStates
from btcp.lossy_layer import LossyLayer
from btcp.constants import *
from btcp.GBN import GBN
import time
from btcp.resettable_timer import ResettableTimer

import queue
import logging
import struct


logger = logging.getLogger(__name__)


class BTCPClientSocket(BTCPSocket):
    """bTCP client socket
    A client application makes use of the services provided by bTCP by calling
    connect, send, shutdown, and close.

    You're implementing the transport layer, exposing it to the application
    layer as a (variation on) socket API.

    To implement the transport layer, you also need to interface with the
    network (lossy) layer. This happens by both calling into it
    (LossyLayer.send_segment) and providing callbacks for it
    (BTCPClientSocket.lossy_layer_segment_received, lossy_layer_tick).

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
        """Constructor for the bTCP client socket. Allocates local resources
        and starts an instance of the Lossy Layer.

        You can extend this method if you need additional attributes to be
        initialized, but do *not* call connect from here.
        """
        logger.debug("__init__ called")
        super().__init__(window, timeout)
        self._lossy_layer = LossyLayer(self, CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT)
        self.packet_handler = GBN(window_size=window, lossy_layer=self._lossy_layer, ISN=0) # TODO: CHANGE ISN IN HAND SHAKE / NEGOTIATION.

        # The data buffer used by send() to send data from the application
        # thread into the network thread. Bounded in size.
        self._sendbuf = queue.Queue(maxsize=1000)
        logger.info("Socket initialized with sendbuf size 1000")

		# max tries and tries
        self._MAX_TRIES = 10
        self._SYN_TRIES = 0
        self._FIN_TRIES = 0

    def lossy_layer_tick_a (self):
        print("client: going through the timer")
        self.lossy_layer_tick()

    ###########################################################################
    ### The following section is the interface between the transport layer  ###
    ### and the lossy (network) layer. When a segment arrives, the lossy    ###
    ### layer will call the lossy_layer_segment_received method "from the   ###
    ### network thread". In that method you should handle the checking of   ###
    ### the segment, and take other actions that should be taken upon its   ###
    ### arrival.                                                            ###
    ###                                                                     ###
    ### Of course you can implement this using any helper methods you want  ###
    ### to add.                                                             ###
    ###########################################################################

    def lossy_layer_segment_received(self, segment):
        """Called by the lossy layer whenever a segment arrives.

        Things you should expect to handle here (or in helper methods called
        from here):
            - checksum verification (and deciding what to do if it fails)
            - receiving syn/ack during handshake
            - receiving ack and registering the corresponding segment as being
              acknowledged
            - receiving fin/ack during termination
            - any other handling of the header received from the server

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

        print("client: resetting the timer, a segment has been rcvd")

        if not len(segment) == SEGMENT_SIZE:
            raise NotImplementedError("Segment not long enough handle not implemented")
        else:
            header, data = segment[:HEADER_SIZE], segment[HEADER_SIZE:]
            seq_num, ack_num, flags, window, data_len, checksum = BTCPSocket.unpack_segment_header(header)
            print(f"client_lossy_layer_rcvd: flags: {flags}")
            if not BTCPSocket.verify_checksum(segment):
                # TODO: handle the case where the checksum is not correct.
                # probably just ignore / drop the packet.
                pass
            else:
                match self._state: # just consider the transitions in the FSM where we receive anything. the rest is not handled here.
                    case BTCPStates.SYN_SENT:
                        self._syn_segment_received(segment)
                    case BTCPStates.ESTABLISHED:
                        print(f"flags: {flags}, in ESTABLISHED, so need to send ack")
                        self._established_segment_received(segment)
                    case BTCPStates.FIN_SENT:
                        self._fin_sent_segment_received(segment)

    def _syn_segment_received(self, segment):
        """
        recv SYN|ACK -> send ACK
        """
        print(">client: rcvd in [ syn seg rvcd ]")

        seq_num, ack_num, flags, window, data_len, checksum = BTCPSocket.unpack_segment_header(segment[:HEADER_SIZE])
        if flags & 7 == 6 and ack_num == self._ISN + 1: # check iff syn and ack flags are set, and if the ack is the expected ack.
            pseudo_header = BTCPSocket.build_segment_header(seqnum=ack_num, acknum=seq_num+1, ack_set=True)
            header = BTCPSocket.build_segment_header(seqnum=ack_num, acknum=seq_num+1, ack_set=True, checksum=BTCPSocket.in_cksum(pseudo_header))
            segment = header + bytes(PAYLOAD_SIZE)
            self._lossy_layer.send_segment(segment)


            print("--> client: going to ESTABLISHED")

            self.update_state(BTCPStates.ESTABLISHED)
            print("CURRENT SEQUENCE NUMBER OF CLIENT WHEN TURNED ESTABLISHED:")
            print(self.packet_handler.current_SN)
            # wellicht nog ISN/SN aanpassen (zowel in btcpsocket class als de packet handler)

        pass

    def _established_segment_received(self, segment):
        print(">client: rcvd in [ est seg rvcd ]")
        seq_num, ack_num, flags, window, data_len, checksum = BTCPSocket.unpack_segment_header(segment[:HEADER_SIZE])
        if flags != fSYN + fACK:
            self.packet_handler.handle_rcvd_seg(segment)
        else: # we are dealing with SYN | ACK
            print(f"client_socket: acknum: {ack_num}, ISN: {self._ISN}")
            if ack_num == self._ISN + 1:
                pseudo_header = BTCPSocket.build_segment_header(seqnum=ack_num, acknum=seq_num+1, ack_set=True)
                header = BTCPSocket.build_segment_header(seqnum=ack_num, acknum=seq_num+1, ack_set=True, checksum=BTCPSocket.in_cksum(pseudo_header))
                segment = header + bytes(PAYLOAD_SIZE)
                self._lossy_layer.send_segment(segment)
    
    def _fin_sent_segment_received(self, segment):
        """
        recv ACK, process ACK
        recv FIN|ACK -> send ACK
        """
        print(">client: rcvd in [ fin sent rvcd ]")
        seq_num, ack_num, flags, window, data_len, checksum = BTCPSocket.unpack_segment_header(segment[:HEADER_SIZE])
        if flags == fACK:
            self.packet_handler.handle_rcvd_seg(segment) # TODO ? - dieks

        if flags == fFIN + fACK:
            # TODO: what seqnum and acknum to use?

            pseudo_header = BTCPSocket.build_segment_header(seqnum=0, acknum=seq_num, ack_set=True, window=self._window)
            header = BTCPSocket.build_segment_header(seqnum=0, acknum=seq_num, ack_set=True, window=self._window, checksum=BTCPSocket.in_cksum(pseudo_header))

            segment = header + bytes(PAYLOAD_SIZE)

            self._lossy_layer.send_segment(segment)
            self.update_state(BTCPStates.CLOSED)

            # TODO: FIX TIMEOUT && MAX RETRIES EXCEEDED.



    def lossy_layer_tick(self):
        """Called by the lossy layer whenever no segment has arrived for
        TIMER_TICK milliseconds. Defaults to 100ms, can be set in constants.py.

        NOTE: Will NOT be called if segments are arriving; do not rely on
        simply counting calls to this method for an accurate timeout. If 10
        segments arrive, each 99 ms apart, this method will NOT be called for
        over a second!

        The primary use for this method is to be able to do things in the
        "network thread" even while no segments are arriving -- which would
        otherwise trigger a call to lossy_layer_segment_received.

        For example, checking for timeouts on acknowledgement of previously
        sent segments -- to trigger retransmission -- should work even if no
        segments are being received. Although you can't count these ticks
        themselves for the timeout, you can trigger the check from here.

        You will probably see some code duplication of code that doesn't handle
        the incoming segment among lossy_layer_segment_received and
        lossy_layer_tick. That kind of duplicated code would be a good
        candidate to put in a helper method which can be called from either
        lossy_layer_segment_received or lossy_layer_tick.
        """
        logger.debug("lossy_layer_tick called")

        print("client: lossy_layer_tick", self._state)

        if self._state != BTCPStates.CLOSED:
            print("client: restart a timer, NOT CLOSED")

        match self._state:
            case BTCPStates.SYN_SENT:
                if self._SYN_TRIES > self._MAX_TRIES:
                    self._SYN_TRIES = 0
                    self.update_state(BTCPStates.CLOSED)
                else:
                    self._SYN_TRIES += 1
                    
                    # re-send connecting SYN
                    pseudo_header = BTCPSocket.build_segment_header(seqnum=self._ISN, acknum=0, syn_set=True) # Do we keep acknum = 0 here?
                    header = BTCPSocket.build_segment_header(seqnum=self._ISN, acknum=0, syn_set=True, checksum=BTCPSocket.in_cksum(pseudo_header))
                    segment = header + bytes(PAYLOAD_SIZE)

                    self._lossy_layer.send_segment(segment)
            case BTCPStates.ESTABLISHED:
                # the packet handler will handle all timers and will already know that there
                # have been no incomming packets, so we do not have to call anything in the socket
                pass
            case BTCPStates.FIN_SENT:
                print("ENTERING FIN SENT CASE")
                if self._FIN_TRIES > self._MAX_TRIES:
                    self._FIN_TRIES = 0

                    self.update_state(BTCPStates.CLOSED)
                else:
                    self._FIN_TRIES += 1
                    # TODO: sent a FIN
                    pseudo_header = BTCPSocket.build_segment_header(seqnum=self.packet_handler.current_SN, acknum=0, fin_set=True, window=self._window)
                    header = BTCPSocket.build_segment_header(seqnum=self.packet_handler.current_SN, acknum=0, fin_set=True, window=self._window, checksum=BTCPSocket.in_cksum(pseudo_header))
            
                    self._lossy_layer.send_segment(header + bytes(PAYLOAD_SIZE))
            case BTCPStates.CLOSED:
                print("client: closed, stopping the timer")
            
        return



    ###########################################################################
    ### You're also building the socket API for the applications to use.    ###
    ### The following section is the interface between the application      ###
    ### layer and the transport layer. Applications call these methods to   ###
    ### connect, shutdown (disconnect), send data, etc. Conceptually, this  ###
    ### happens in "the application thread".                                ###
    ###                                                                     ###
    ### You *can*, from this application thread, send segments into the     ###
    ### lossy layer, i.e. you can call LossyLayer.send_segment(segment)     ###
    ### from these methods without ensuring that happens in the network     ###
    ### thread. However, if you do want to do this from the network thread, ###
    ### you should use the lossy_layer_tick() method above to ensure that   ###
    ### segments can be sent out even if no segments arrive to trigger the  ###
    ### call to lossy_layer_segment_received. When passing segments between ###
    ### the application thread and the network thread, remember to use a    ###
    ### Queue for its inherent thread safety.                               ###
    ###                                                                     ###
    ### Note that because this is the client socket, and our (initial)      ###
    ### implementation of bTCP is one-way reliable data transfer, there is  ###
    ### no recv() method available to the applications. You should still    ###
    ### be able to receive segments on the lossy layer, however, because    ###
    ### of acknowledgements and synchronization. You should implement that  ###
    ### above.                                                              ###
    ###########################################################################

    def connect(self):
        """Perform the bTCP three-way handshake to establish a connection.

        connect should *block* (i.e. not return) until the connection has been
        successfully established or the connection attempt is aborted. You will
        need some coordination between the application thread and the network
        thread for this, because the syn/ack from the server will be received
        in the network thread.

        Hint: assigning to a boolean or enum attribute in thread A and reading
        it in a loop in thread B (preferably with a short sleep to avoid
        wasting a lot of CPU time) ensures that thread B will wait until the
        boolean or enum has the expected value. You can also put some kind of
        "signal" (e.g. BTCPSignals.CONNECT, or BTCPStates.FIN_SENT) in a Queue,
        and use a blocking get() on the other side to receive that signal.

        Since Python uses duck typing, and Queues can handle mixed types,
        you could even use the same queue to send a "connect signal", then
        all data chunks, then a "shutdown signal", into the network thread.
        That will take some tricky handling, however.

        We do not think you will need more advanced thread synchronization in
        this project.
        """
        if not self._state == BTCPStates.CLOSED:
            logger.debug("connect was called while not in closed. do nothing.")
            return 
        
        logger.debug("connect called")
        ISN = self._ISN
        # send 16 bit SNF, set SYN FLAG
        pseudo_header = BTCPSocket.build_segment_header(seqnum=self._ISN, acknum=0, syn_set=True) # Do we keep acknum = 0 here?
        header = BTCPSocket.build_segment_header(seqnum=self._ISN, acknum=0, syn_set=True, checksum=BTCPSocket.in_cksum(pseudo_header))
        segment = header + bytes(PAYLOAD_SIZE)

        self._lossy_layer.send_segment(segment)
        self.update_state(BTCPStates.SYN_SENT)

        print("client: starting a timer at connect")

        while self._state != BTCPStates.ESTABLISHED and self._state != BTCPStates.CLOSED:
            time.sleep(0.1)


    def send(self, data):
        """Send data originating from the application in a reliable way to the
        server.

        This method should *NOT* block waiting for acknowledgement of the data.


        You are free to implement this however you like, but the following
        explanation may help to understand how sockets *usually* behave and you
        may choose to follow this concept as well:

        The way this usually works is that "send" operates on a "send buffer".
        Once (part of) the data has been successfully put "in the send buffer",
        the send method returns the number of bytes it was able to put in the
        buffer. The actual sending of the data, i.e. turning it into segments
        and sending the segments into the lossy layer, happens *outside* of the
        send method (e.g. in the network thread).
        If the socket does not have enough buffer space available, it is up to
        the application to retry sending the bytes it was not able to buffer
        for sending.

        Again, you should feel free to deviate from how this usually works.
        Note that our rudimentary implementation here already chunks the data
        in maximum 1008-byte bytes objects because that's the maximum a segment
        can carry. If a chunk is smaller we do *not* pad it here, that gets
        done later.
        """
        logger.debug("send called")
        if self._state == BTCPStates.ESTABLISHED:
            print("client-send: sending data", data)
            return self.packet_handler.send_data(data=data)
        
        print("trying to send data while connection not established")
        return bytes(0)


    def shutdown(self):
        """Perform the bTCP three-way finish to shutdown the connection.

        shutdown should *block* (i.e. not return) until the connection has been
        successfully terminated or the disconnect attempt is aborted. You will
        need some coordination between the application thread and the network
        thread for this, because the fin/ack from the server will be received
        in the network thread.

        Hint: assigning to a boolean or enum attribute in thread A and reading
        it in a loop in thread B (preferably with a short sleep to avoid
        wasting a lot of CPU time) ensures that thread B will wait until the
        boolean or enum has the expected value. We do not think you will need
        more advanced thread synchronization in this project.
        """
        logger.debug("shutdown called")
        
        if self._state != BTCPStates.ESTABLISHED:
            logger.debug("cannot call shutdown when connection is not ESTABLISHED")
        else:   # TODO: check sequence number

            print("<client-shutdown: preparing to shutdown and sending a FIN")
            pseudo_header = BTCPSocket.build_segment_header(seqnum=self.packet_handler.current_SN+1, acknum=0, fin_set=True, window=self._window)
            header = BTCPSocket.build_segment_header(seqnum=self.packet_handler.current_SN+1, acknum=0, fin_set=True, window=self._window, checksum=BTCPSocket.in_cksum(pseudo_header))
            
            self._lossy_layer.send_segment(header + bytes(PAYLOAD_SIZE))

            self.packet_handler.current_SN += 1 
            self.update_state(BTCPStates.FIN_SENT)

            # self.packet_handler.ack_timer.stop()
            print("client: starting a timer at shutdown")

            while not self._state == BTCPStates.CLOSED:
                print("client: waiting to close", self._state)
                time.sleep(0.1)


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
