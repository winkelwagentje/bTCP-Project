import struct
import logging
from enum import IntEnum


logger = logging.getLogger(__name__)


class BTCPStates(IntEnum):
    """Enum class that helps you implement the bTCP state machine.

    Don't use the integer values of this enum directly. Always refer to them as
    BTCPStates.CLOSED etc.

    These states are NOT exhaustive! We left out at least one state that you
    will need to implement the bTCP state machine correctly. The intention of
    this enum is to give you some idea for states and how simple the
    transitions between them are.

    Feel free to implement your state machine in a different way, without
    using such an enum.
    """
    CLOSED      = 0
    ACCEPTING   = 1
    SYN_SENT    = 2
    SYN_RCVD    = 3
    FIN_WAIT    = 4
    FIN_SENT    = 5
    CLOSING     = 6
    Listen      = 7


class BTCPSignals(IntEnum):
    """Enum class that you can use to signal from the Application thread
    to the Network thread.

    For example, rather than explicitly change state in the Application thread,
    you could put one of these in a variable that the network thread reads the
    next time it ticks, and handles the state change in the network thread.
    """
    ACCEPT = 1
    CONNECT = 2
    SHUTDOWN = 3


class BTCPSocket:
    """Base class for bTCP client and server sockets. Contains static helper
    methods that will definitely be useful for both sending and receiving side.
    """
    def __init__(self, window, timeout):
        logger.debug("__init__ called")
        self._window = window
        self._timeout = timeout
        self._state = BTCPStates.CLOSED
        logger.debug("Socket initialized with window %i and timeout %i",
                     self._window, self._timeout)


    @staticmethod
    def in_cksum(segment):                              # calculates the internet checksum over the data
                                                        # Signal nonsensical request (checksum of nothing?) with an exception.
                                                        # where segment is assumed to be a bytes object.
        if not segment:
            raise ValueError("Asked to checksum an empty buffer.")
        checksum = 0x0000
        for i in range(0, len(segment), 2):              # consider two bytes each loop.
            if i + 1 < len(segment):                     # case where there are 2 bytes or more left two take into the checksum
                checksum += (segment[i] << 8) + segment[i + 1]
            else:                                       # only 1 byte left to add to the checksum
                checksum += segment[i] << 8
            if checksum > 0xFFFF:                       # check if we have a carry out
                checksum = (checksum & 0xFFFF) + 1      # bitmask the checksum to get rid of the carry, add 1 to the back.
        return  ~checksum & 0xFFFF                      # invert bits at final step, combine it into a bytes object again
                                                        # assuming the desired length of the checksum is 2 bytes.


    @staticmethod
    def verify_checksum(segment):
        """Verify that the checksum indicates is an uncorrupted segment.

        Mind that you change *what* signals that to the correct value(s).
        """
        return BTCPSocket.in_cksum(segment) == 0xFFFF


    @staticmethod
    def build_segment_header(seqnum, acknum,
                             syn_set=False, ack_set=False, fin_set=False,
                             window=0x01, length=0, checksum=0):
        """Pack the method arguments into a valid bTCP header using struct.pack

        This method is given because historically students had a lot of trouble
        figuring out how to pack and unpack values into / out of the header.
        We have *not* provided an implementation of the corresponding unpack
        method (see below), so inspect the code, look at the documentation for
        struct.pack, and figure out what this does, so you can implement the
        unpack method yourself.

        Of course, you are free to implement it differently, as long as you
        do so correctly *and respect the network byte order*.

        You are allowed to change the SYN, ACK, and FIN flag locations in the
        flags byte, but make sure to do so correctly everywhere you pack and
        unpack them.

        The method is written to have sane defaults for the arguments, so
        you don't have to always set all flags explicitly true/false, or give
        a checksum of 0 when creating the header for checksum computation.
        """
        logger.debug("build_segment_header() called")
        flag_byte = syn_set << 2 | ack_set << 1 | fin_set
        logger.debug("build_segment_header() done")
        return struct.pack("!HHBBHH",
                           seqnum, acknum, flag_byte, window, length, checksum)


    @staticmethod
    def unpack_segment_header(header):
        """Unpack the individual bTCP header field values from the header.

        Remember that Python supports multiple return values through automatic
        tupling, so it's easy to simply return all of them in one go rather
        than make a separate method for every individual field.
        """
        logger.debug("unpack_segment_header() called")

        seq_num, ack_num, unused, flags, data_len, checksum = struct.unpack("!HHBBHH", header)

        logger.debug("unpack_segment_header() done")

        return seq_num, ack_num, unused, flags, data_len, checksum

