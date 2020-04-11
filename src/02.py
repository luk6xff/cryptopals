"""
Fixed XOR
Write a function that takes two equal-length buffers and produces their XOR combination.

If your function works properly, then when you feed it the string:
1c0111001f010100061a024b53535009181c

... after hex decoding, and when XOR'd against:
686974207468652062756c6c277320657965

... should produce:
746865206b696420646f6e277420706c6179
"""




def xor_combine(s1, s2):
    assert(len(s1) == len(s2))
    b1 = bytes.fromhex(s1)
    b2 = bytes.fromhex(s2)
    assert(len(b1) == len(b2))
    xored = ''
    for i in range(len(b1)):
        xored += chr(b1[i] ^ b2[i])
    return xored



# s1 = '1c0111001f010100061a024b53535009181c'
# s2 = '686974207468652062756c6c277320657965'
s1 = '1c01'
s2 = '6869'
s_expected = '746865206b696420646f6e277420706c6179'


result = xor_combine(s1, s2)
print(result)
assert(bytes.hex(result) == s_expected)
