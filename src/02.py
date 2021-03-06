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

from xor_utils import xor_strings


s1 = '1c0111001f010100061a024b53535009181c'
s2 = '686974207468652062756c6c277320657965'
s_expected = '746865206b696420646f6e277420706c6179'


s_result = xor_strings(s1, s2)
print(bytes.hex(s_result), s_expected)
assert(bytes.hex(s_result) == s_expected)
