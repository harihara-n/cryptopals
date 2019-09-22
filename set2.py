#!./bin/python3.7

#
# Cryptopals Set 2 - https://cryptopals.com/sets/2
#

from Crypto.Cipher import AES
import pdb
import requests
import set1
import secrets

def do_pkcs7_padding(byte_string, pad_length):
  return_byte_string = bytes(byte_string)
  length_to_pad = pad_length - len(return_byte_string)
  return_byte_string += bytes([length_to_pad] * length_to_pad)
  return return_byte_string


def aes128_cbc_decrypt(ciphertext, iv, key):
  aes = AES.new(key, AES.MODE_ECB)
  def decrypt_chunk(chunk, iv):
    return set1.xor_two_byte_strings(aes.decrypt(chunk), iv)

  chunks = set1.split_into_n_sized_chunks(ciphertext, 16)
  decrypted_bytes = b''
  for i, chunk in enumerate(chunks):
    if i == 0:
      decrypted_bytes += decrypt_chunk(bytes(chunk), iv)
    else:
      decrypted_bytes += decrypt_chunk(bytes(chunk), chunks[i-1])
  return decrypted_bytes

def aes128_cbc_encrypt(text, iv, key):
  aes = AES.new(key, AES.MODE_ECB)
  def encrypt_chunk(chunk, iv):
    return aes.encrypt(set1.xor_two_byte_strings(chunk, iv))

  chunks = set1.split_into_n_sized_chunks(text, 16)
  encrypted_bytes = b''
  for i, chunk in enumerate(chunks):
    if i == 0:
      prev_encrypted_bytes = encrypt_chunk(bytes(chunk), iv)
    else:
      prev_encrypted_bytes = encrypt_chunk(bytes(chunk), prev_encrypted_bytes)
    encrypted_bytes += prev_encrypted_bytes
  return encrypted_bytes

def generate_aes_key(num_bytes):
  return secrets.token_bytes(num_bytes)


if __name__ == '__main__':
  # Challenge 9: https://cryptopals.com/sets/2/challenges/9
  string = "YELLOW SUBMARINE"
  print("Challenge 9: {0}".format(do_pkcs7_padding(string.encode('utf-8'), 20)))

  # Challenge 10: https://cryptopals.com/sets/2/challenges/10
  b64_string = requests.get('https://cryptopals.com/static/challenge-data/10.txt').text.strip()
  byte_string = set1.b64_string_to_byte_string(b64_string)
  iv = bytes([0] * 16)
  key = b'YELLOW SUBMARINE'
  print("Challenge 10: {0}".format(aes128_cbc_decrypt(byte_string, iv, key)))
