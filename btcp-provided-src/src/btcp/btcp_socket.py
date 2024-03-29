import struct
import logging
from enum import IntEnum
from btcp.constants import *
import random as r

logger = logging.getLogger(__name__)


class BTCPStates(IntEnum):
    CLOSED      = 0
    ACCEPTING   = 1
    SYN_SENT    = 2
    SYN_RCVD    = 3
    FIN_WAIT    = 4
    FIN_SENT    = 5
    CLOSING     = 6
    LISTEN      = 7
    ESTABLISHED = 8


class BTCPSignals(IntEnum):
    ACCEPT = 1
    CONNECT = 2
    SHUTDOWN = 3


class BTCPSocket:
    def __init__(self, window, timeout):
        logger.debug("__init__ called")
        self._window = window
        self._timeout = timeout
        self._state = BTCPStates.CLOSED
        self._ISN = self.reset_ISN()
        self._ISN_sender = 0
        logger.debug("Socket initialized with window %i and timeout %i",
                     self._window, self._timeout)

    def update_state(self, new_state):
        self._state = new_state

    def reset_ISN(self):
        return r.randint(0,MAX_INT-1)

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
        return BTCPSocket.in_cksum(segment) == 0x0000

    @staticmethod
    def build_segment_header(seqnum, acknum,
                             syn_set=False, ack_set=False, fin_set=False,
                             window=0x01, length=0, checksum=0):
        logger.debug("build_segment_header() called")
        flag_byte = syn_set << 2 | ack_set << 1 | fin_set
        logger.debug("build_segment_header() done")
        return struct.pack("!HHBBHH",
                           seqnum, acknum, flag_byte, window, length, checksum)


    @staticmethod
    def unpack_segment_header(header):
        seq_num, acknum, flag_byte, window, length, checksum = struct.unpack("!HHBBHH", header)
        flag_byte = flag_byte & 0b111

        return seq_num, acknum, flag_byte, window, length, checksum
    
    @staticmethod
    def build_segment(seqnum, acknum,
                             syn_set=False, ack_set=False, fin_set=False,
                             window=0x01, length=0, payload=bytes(PAYLOAD_SIZE)):
        pseudo_header = BTCPSocket.build_segment_header(seqnum, acknum, syn_set, ack_set, fin_set, window, length)
        header = BTCPSocket.build_segment_header(seqnum, acknum, syn_set, ack_set, fin_set, window, length, checksum=BTCPSocket.in_cksum(pseudo_header+payload))
        segment = header + payload
        return segment
    
    @staticmethod
    def increment(var, incr=1, mod=MAX_INT):
        return (var+incr) % mod

