from binascii import unhexlify


def swap_endian_word(hex_word):
    """Swaps the endianness of a hexidecimal string of a word and converts to a binary string."""

    message = unhexlify(hex_word)
    if len(message) != 4:
        raise ValueError('Must be 4-byte word')
    return message[::-1]


def swap_endian_words(hex_words):
    """Swaps the endianness of a hexidecimal string of words and converts to binary string."""

    message = unhexlify(hex_words)
    if len(message) % 4 != 0:
        raise ValueError('Must be 4-byte word aligned')
    return ''.join([message[4 * i: 4 * i + 4][::-1] for i in range(0, len(message) // 4)])


def human_readable_hashrate(hashrate):
    """Returns a human readable representation of hashrate."""

    if hashrate < 1000:
        return '%2f hashes/s' % hashrate
    if hashrate < 10000000:
        return '%2f khashes/s' % (hashrate / 1000)
    if hashrate < 10000000000:
        return '%2f Mhashes/s' % (hashrate / 1000000)
    return '%2f Ghashes/s' % (hashrate / 1000000000)
