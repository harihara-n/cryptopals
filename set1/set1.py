#!./bin/python3.7

#
# Cryptopals Set 1 - https://cryptopals.com/sets/1
#

from binascii import hexlify, unhexlify
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
import itertools
import requests
import pdb

def hex_string_to_byte_string(hex_string):
  return unhexlify(hex_string)

def byte_string_to_b64_string(byte_string):
  return b64encode(byte_string)

def hex_string_to_b64_string(hex_string):
  return byte_string_to_b64_string(hex_string_to_byte_string(hex_string))

def byte_string_to_hex_string(byte_string):
  return hexlify(byte_string)

def b64_string_to_byte_string(b64_string):
  return b64decode(b64_string)

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


def xor_byte_string_with_repeating_bytes(byte_string, repeating_bytes):
  return_bytes = b''
  for i, byte in enumerate(byte_string):
    return_bytes += (bytes([byte ^ repeating_bytes[i % len(repeating_bytes)]]))
  return return_bytes

def encrypt_with_repeating_key_xor(string, key):
  return byte_string_to_hex_string(xor_byte_string_with_repeating_bytes(string.encode('utf-8'), key.encode('utf-8')))

def hamming_distance_between_two_byte_integers(byte1, byte2):
  xor_value = byte1 ^ byte2
  set_bits = 0
  while xor_value > 0:
    set_bits += (xor_value % 2)
    xor_value = xor_value >> 1
  return set_bits

def hamming_distance_between_two_byte_strings(byte_string_1, byte_string_2):
  # assume equal length byte strings.
  return sum([hamming_distance_between_two_byte_integers(x, y) for x, y in zip(byte_string_1, byte_string_2)])

def split_into_n_sized_chunks(byte_string, n):
  chunks = list(itertools.zip_longest(*[byte_string[i::n] for i in range(0, min(n, len(byte_string)))]))
  chunks = list(map(lambda x: list(x), chunks))
  # Since we zip_longest, last chunk might contain nulls to pad for equal length. Remove it.
  chunks[-1] = list(filter(None, chunks[-1]))
  return chunks

# We will try key sizes from 2 - 50
def get_x_most_possible_key_sizes_for_cipher(cipher_byte_string, x):
  possible_key_sizes = []
  for n in range(2, 51):
    score = 0
    split_arrays = split_into_n_sized_chunks(cipher_byte_string, 2*n)
    if len(split_arrays[-1]) != 2*n:
      del split_arrays[-1]
    for split_array in split_arrays:
      score += hamming_distance_between_two_byte_strings(*split_into_n_sized_chunks(split_array, n))
    if len(possible_key_sizes) < x:
      possible_key_sizes.append((score, n))
      possible_key_sizes.sort()
    elif possible_key_sizes[-1][0] > score:
      possible_key_sizes[-1] = ((score, n))
      possible_key_sizes.sort()
  return list(map(lambda x: x[1], possible_key_sizes))

def get_possible_key_for_keysizes(byte_string, possible_key_sizes):
  keys = []
  for key_size in possible_key_sizes:
    chunks = split_into_n_sized_chunks(byte_string, key_size)
    if len(chunks) != 2*key_size:
      del chunks[-1]
    transposed_chunks = [list(x) for x in zip(*chunks)]

    key = b''
    for i in range(key_size):
      highest_scored_byte = None
      for byte in range(256):
        xored = xor_byte_string_with_byte(bytes(transposed_chunks[i]), byte)
        score = score_byte_string_on_english_characters_frequency(xored)
        if highest_scored_byte is None:
          highest_scored_byte = ((score, byte))
        elif score > highest_scored_byte[0]:
          highest_scored_byte = ((score, byte))
      key += bytes([highest_scored_byte[1]])

    keys.append(key)
  return keys


if __name__ == "__main__":
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

  # Challenge 4: https://cryptopals.com/sets/1/challenges/4
  hex_strings = requests.get('https://cryptopals.com/static/challenge-data/4.txt').text.split()
  answer_bytes_string = b''
  max_score = 0
  for hex_string in hex_strings:
    for byte in range(256):
      bytes_string = xor_byte_string_with_byte(hex_string_to_byte_string(hex_string), byte)
      score = score_byte_string_on_english_characters_frequency(bytes_string)
      if max_score < score:
        max_score = score
        answer_bytes_string = bytes_string
  print("Challenge 4: {0}".format(answer_bytes_string))

  # Challenge 5: https://cryptopals.com/sets/1/challenges/5
  string = '''Burning 'em, if you ain't quick and nimble
  I go crazy when I hear a cymbal'''
  key = "ICE"
  print("Challenge 5: {0}".format(encrypt_with_repeating_key_xor(string, key)))

  # Challenge 6: https://cryptopals.com/sets/1/challenges/6
  print("Challenge 6: ")
  b64_string = requests.get('https://cryptopals.com/static/challenge-data/6.txt').text.strip()
  byte_string = b64_string_to_byte_string(b64_string)
  key_sizes = get_x_most_possible_key_sizes_for_cipher(byte_string, 4)
  keys = get_possible_key_for_keysizes(byte_string, key_sizes)
  for key in keys:
    original_byte_string = xor_byte_string_with_repeating_bytes(byte_string, key)
    print(original_byte_string)
    print(key)

  # Challenge 7: https://cryptopals.com/sets/1/challenges/7
  b64_string = requests.get('https://cryptopals.com/static/challenge-data/7.txt').text.strip()
  encrypted_byte_string = b64_string_to_byte_string(b64_string) 
  key = b'YELLOW SUBMARINE'
  aes = AES.new(key, AES.MODE_ECB)
  print("Challenge 7: {0}".format(aes.decrypt(encrypted_byte_string)))

  # Challenge 7: https://cryptopals.com/sets/1/challenges/8
  hex_strings = requests.get('https://cryptopals.com/static/challenge-data/8.txt').text.strip().split('\n')
  # In the hex string encrypted using AES 128 in ECB mode, there is a chance that some two 16 byte blocks will
  # be the same. So, we select all the hex_strings in which there is such an occurrence.
  possible_aes_128_ecb_ciphers = []
  for hex_string in hex_strings:
    chunks = list(map(lambda x: ''.join(x), split_into_n_sized_chunks(hex_string, 32)))
    if len(chunks) > len(set(chunks)):
      possible_aes_128_ecb_ciphers.append(hex_string)
  print("Challenge 8: {0}".format(possible_aes_128_ecb_ciphers))
