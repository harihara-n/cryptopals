#!/usr/local/bin/python3.7

#
# Cryptopals Set 1 - https://cryptopals.com/sets/1
#

from binascii import hexlify, unhexlify
from base64 import b64encode

def hex_string_to_byte_string(hex_string):
  return unhexlify(hex_string)

def byte_string_to_b64_string(byte_string):
  return b64encode(byte_string)

def hex_string_to_b64_string(hex_string):
  return byte_string_to_b64_string(hex_string_to_byte_string(hex_string))

def byte_string_to_hex_string(byte_string):
  return hexlify(byte_string)

def xor_two_byte_strings(byte_string_1, byte_string_2):
  bytearray_1 = bytearray(byte_string_1)
  bytearray_2 = bytearray(byte_string_2)
  bytearray_1.reverse()
  bytearray_2.reverse()

  min_len_bytearray = (byte_array_2 if len(bytearray_1) > len(bytearray_2) else bytearray_1)
  max_len_bytearray = (byte_array_1 if len(bytearray_1) > len(bytearray_2) else bytearray_2)

  bytearray_result = bytearray([])
  for index in range(len(min_len_bytearray)):
    bytearray_result.append(bytearray_1[index] ^ bytearray_2[index])
  for index in range(len(min_len_bytearray), len(max_len_bytearray)):
    bytearray_result.append(max_len_bytearray[index])

  bytearray_result.reverse()
  return bytes(bytearray_result)

def xor_two_hex_strings(hex_string_1, hex_string_2):
  return byte_string_to_hex_string(xor_two_byte_strings(hex_string_to_byte_string(hex_string_1), hex_string_to_byte_string(hex_string_2)))

def xor_byte_string_with_byte(byte_string, byte):
  return_bytes = b''
  for i in range(len(byte_string)):
    return_bytes += (bytes([byte_string[i]^byte]))
  return return_bytes

def score_byte_string_on_english_characters_frequency(bytes_string):
  character_frequencies = {
    'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
    'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
    'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
    'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
    'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
    'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
    'y': .01974, 'z': .00074, ' ': .13000
  }
  score = 0
  for byte in bytes_string:
    score += character_frequencies.get(chr(byte), 0)
  return score


# Challenge 1: https://cryptopals.com/sets/1/challenges/1
hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
print("Challenge 1: {0}".format(hex_string_to_b64_string(hex_string)))

# Challenge 2: https://cryptopals.com/sets/1/challenges/2
hex_string_1 = "1c0111001f010100061a024b53535009181c"
hex_string_2 = "686974207468652062756c6c277320657965"
print("Challenge 2: {0}".format(xor_two_hex_strings(hex_string_1, hex_string_2)))

# Challenge 3: https://cryptopals.com/sets/1/challenges/3
hex_string = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
answer_bytes_string = b''
max_score = 0
for byte in range(256):
  bytes_string = xor_byte_string_with_byte(hex_string_to_byte_string(hex_string), byte)
  score = score_byte_string_on_english_characters_frequency(bytes_string)
  if max_score < score:
    max_score = score
    answer_bytes_string = bytes_string
print("Challenge 3: {0}".format(answer_bytes_string))
