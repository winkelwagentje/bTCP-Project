def internet_checksum(buffer):
    # calculates the internet checksum over the data
    # where data is assumed to be a bytes object.
    # Signal nonsensical request (checksum of nothing?) with an exception.
    if not buffer:
        raise ValueError("Asked to checksum an empty buffer.")
    checksum = 0x0000
    for i in range(0, len(buffer), 2):              # consider two bytes each loop.
        if i + 1 < len(buffer):                     # case where there are 2 bytes or more left two take into the checksum
            checksum += (buffer[i] << 8) + buffer[i + 1]
        else:                                       # only 1 byte left to add to the checksum
            checksum += buffer[i] << 8
        if checksum > 0xFFFF:                       # check if we have a carry out
            checksum = (checksum & 0xFFFF) + 1      # bitmask the checksum to get rid of the carry, add 1 to the back.
    return  ~checksum & 0xFFFF                      # invert bits at final step, combine it into a bytes object again
                                                    # assuming the desired length of the checksum is 2 bytes.