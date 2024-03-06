def internet_checksum(data): # calculates the internet checksum over the data
                             # where data is assumed to be a bytes object.
    checksum = 0
    for i in range(0, len(data), 2): #consider two bytes each loop.
        if i + 1 < len(data): # case where there are 2 bytes or more left two take into the checksum
            checksum += (data[i] << 8) + data[i + 1]
        else:                 # only 1 byte left to add to the checksum
            checksum += data[i]
        if checksum > 0xFFFF: #check if we have a carry out
            checksum = (checksum & 0xFFFF) + 1 #bitmask the checksum to get rid of the carry, add 1 to the back.
    return (~checksum).to_bytes(2, byteorder='big') # invert bits at final step, combine it into a bytes object again
                                                    # assuming the desired length of the checksum is 2 bytes.
    
# some testing can be done below:
data = b'\xFF\xFF\xFF\xFF'
checksum = internet_checksum(data)
print(checksum.hex())