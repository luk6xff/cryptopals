from frequency import english_test


def xor_bytes(b1, b2):
    assert(len(b1) == len(b2))
    return bytes([x^y for x,y in zip(b1, b2)])


def xor_strings(s1, s2):
    assert(len(s1) == len(s2))
    b1 = bytes.fromhex(s1)
    b2 = bytes.fromhex(s2)
    return xor_bytes(b1, b2)


def xor_single_char_key(msg, key):
    return xor_strings(msg, [key]*len(msg))


def break_xor_char_key(ciphertext, quality_test=english_test):
    return rank_xor_char_keys(ciphertext, quality_test)[0]


def rank_xor_char_keys(ciphertext, quality_test=english_test):
    possible_keys = range(256)
    decryptions = [(key, xor_single_char_key(ciphertext, key)) for key in possible_keys]
    # sort to get best quality ratio
    best_decryptions = sorted(decryptions,
                                key=lambda key_decryption:
                                (quality_test(key_decryption[1]),
                                key_decryption[1]),
                                reverse=True)
    keys = [key for key, _ in best_decryptions]
    return keys