#!./bin/python3.7

#
# Cryptopals Set 2 - https://cryptopals.com/sets/2
#

from Crypto.Cipher import AES
import pdb
import requests
import set1
import secrets
from collections import Counter

def do_pkcs7_padding(byte_string, pad_length):
  return_byte_string = bytes(byte_string)
  length_to_pad = pad_length - (len(return_byte_string) % pad_length)
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

def encryption_oracle(input_bytes):
  key = generate_aes_key(16)

  # Prepend prepend_num_bytes random bytes. Choose prepend_num_bytes randomly from 5 - 10.
  # Also postpend random bytes till you reach multiple of 16 bytes in length.
  prepend_num_bytes = 5 + secrets.randbelow(6)
  postpend_num_bytes = 5 + secrets.randbelow(6)
  input_bytes = do_pkcs7_padding(
    secrets.token_bytes(prepend_num_bytes) + input_bytes + secrets.token_bytes(postpend_num_bytes),
    16,
  )

  # Choose 0 or 1 at random
  # For 0, choose ECB mode.
  # For 1, choose CBC mode.
  random_mode = secrets.randbelow(2)

  if random_mode == 0:
    print("Using AES Mode: ECB")
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(input_bytes)

  print("Using AES Mode: CBC")
  iv = secrets.token_bytes(16)
  return aes128_cbc_encrypt(input_bytes, iv, key)

def detect_aes_mode_for_oracle():
  # We provide an input with 43 same bytes (we choose byte 100)
  input_bytes = bytes([100]*43)
  encrypted_bytes = encryption_oracle(input_bytes)

  # If it is EBC mode, there WILL be two 16 bytes long bytes sequence, occurring after one another
  # that will have the same byte sequence.
  # If not, it is CBC.
  def is_ecb_condition(encrypted_bytes, index):
    for x in range(16):
      if encrypted_bytes[index + x] != encrypted_bytes[index + x + 16]:
        return False
    return True

  counter = Counter(encrypted_bytes)
  is_ecb = False
  for i, byte in enumerate(encrypted_bytes):
    if i + 31 > len(encrypted_bytes):
      break
    if counter[byte] > 1:
      if is_ecb_condition(encrypted_bytes, i):
        is_ecb = True
        break
  if is_ecb:
    print("Detected AES mode: ECB")
  else:
    print("Detected AES mode: CBC")

def encryption_oracle_modified(input_bytes, key):
  unknown_b64_string = '''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
  aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
  dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
  YnkK'''
  unknown_bytes = set1.b64_string_to_byte_string(unknown_b64_string)
  input_bytes = do_pkcs7_padding(input_bytes + unknown_bytes, 16)
  aes = AES.new(key, AES.MODE_ECB)
  return aes.encrypt(input_bytes)

def find_appended_bytes():
  key = generate_aes_key(16)
  discovered_bytes = bytes([])
  for x in range(143, 4, -1):
    test_bytes = bytes([100] * x)
    encrypted_bytes_dict = dict()
    for byte in range(256):
      encrypted_bytes = encryption_oracle_modified(test_bytes + discovered_bytes + bytes([byte]), key)
      encrypted_bytes_dict[encrypted_bytes[:144]] = byte
    actual_encrypted_bytes = encryption_oracle_modified(test_bytes, key)[:144]
    byte = encrypted_bytes_dict.get(actual_encrypted_bytes, None)
    if byte == None:
      raise 'Something went wrong...'
    discovered_bytes += bytes([byte])
  return discovered_bytes

def decode_key_value_string(string):
  return dict(map(lambda kv: tuple(kv.split("=")), string.split("&")))

def profile_for_encrypted(email):
  if "&" in email or "=" in email:
    raise "email: {0} cannot contain & or = characters".format(email)
  key = '"provide" that to the "attacker"'
  return aes_ecb_encrypt("email={0}&uid=10&role=user".format(email).encode('utf-8'), key)

def decrypt_encrypted_profile(encrypted_bytes):
  key = '"provide" that to the "attacker"'
  return decrypt_aes_ecb_encrypted_user_profile(encrypted_bytes, key)

def aes_ecb_encrypt(byte_string, key):
  aes = AES.new(key, AES.MODE_ECB)
  byte_string = do_pkcs7_padding(byte_string, 16)
  return aes.encrypt(byte_string)

def decrypt_aes_ecb_encrypted_user_profile(encrypted_bytes, key):
  aes = AES.new(key, AES.MODE_ECB)
  decrypted_bytes = aes.decrypt(encrypted_bytes)

  # We might want to switch to a padding where we always padding applied, even if length % 16 == 0.
  # Otherwise there is some ambiguity to knowing if we
  # padded the input bytes or not. Let's move on for now.
  num_padded = decrypted_bytes[-1]
  if num_padded > 0 and num_padded <= 15:
    decrypted_bytes = decrypted_bytes[:-num_padded]
  return decode_key_value_string(decrypted_bytes.decode('utf-8'))


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

  # Challenge 11: https://cryptopals.com/sets/2/challenges/11
  print("Challenge 11:")
  detect_aes_mode_for_oracle()

  # Challenge 12: https://cryptopals.com/sets/2/challenges/12
  # By feeding "A", "AA", "AAA", etc. we find that the length of the append unknown bytes string
  # used in encryption_oracle_modified is 139.
  # By feeding bytes([100]*32), we also verify that encryption_oracle_modified is doing AES in ECB mode.
  print("Challenge 12: {0}".format(find_appended_bytes()))

  # Challenge 13: https://cryptopals.com/sets/2/challenges/13
  print("Challenge 13:")
  encrypted_profile = profile_for_encrypted('foo@bar.com')
  decrypted_profile = decrypt_encrypted_profile(encrypted_profile)
  print(profile_for_encrypted('foo@bar.com'))
  print(decrypted_profile)
  # Now, we need to generate a valid ciphertext, which when decrypted will return a role=admin profile.
  ciphertext = b"\xb5\xb3b\xc6l\x8f\x1d\xe1e\xb6u'\x80\x1c\x0fxf\x07wr\xc6\xadP\xda\xcb\xd3\xc2O\x9c2\xf5\x1d.\xdb\xec\xb4\xc4q\x1cP\x99Hf\x13\xd5\x9b\x04\xaa"
  print(decrypt_encrypted_profile(ciphertext))
