#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import aestools
import random
from Crypto.Cipher import AES


class BadPaddingError(Exception):
    '''Used to implement a padding oracle'''
    pass


def pad(s, blocklen):
    if blocklen > 256:
        return ValueError('The block length must be less than 256!')

    remainder = len(s) % blocklen
    if remainder == 0:
        return s + chr(blocklen) * blocklen
    else:
        return s + chr(blocklen - remainder) * (blocklen - remainder)

def is_padding_ok(s, blocklen):
    padvalue = ord(s[-1])
    if padvalue > blocklen:
        return False

    return all(ord(c) == padvalue for c in s[-padvalue:])

def unpad(s, blocklen):
    if not is_padding_ok(s, blocklen):
        raise BadPaddingError()

    padvalue = ord(s[-1])
    return s[:-padvalue]


def test_cbc_findiv():
    # random 128 bits IV, key
    IV = ''.join(chr(random.randrange(256)) for _ in range(16))
    key = ''.join(chr(random.randrange(256)) for _ in range(16))

    cipher = AES.new(key, AES.MODE_CBC, IV=IV)

    def decfunc(ciphertext):
        return cipher.decrypt(ciphertext)

    assert aestools.cbc_findiv(decfunc, blocklen=16) == IV


def test_cbc_paddingoracle():
    # random 128 bits IV, key
    IV = ''.join(chr(random.randrange(256)) for _ in range(16))
    key = ''.join(chr(random.randrange(256)) for _ in range(16))

    # random plaintext
    length = random.randrange(10, 40)
    plaintext = ''.join(chr(random.randrange(256)) for _ in range(length))

    cipher = AES.new(key, AES.MODE_CBC, IV=IV)
    ciphertext = IV + cipher.encrypt(pad(plaintext, blocklen=16))

    def oraclefunc(ciphertext):
        return is_padding_ok(cipher.decrypt(ciphertext), blocklen=16)

    res = aestools.cbc_paddingoracle(ciphertext, oraclefunc, blocklen=16)
    assert res == pad(plaintext, blocklen=16)


def test_ecb_chosenprefix():
    # random 128 bits key
    key = ''.join(chr(random.randrange(256)) for _ in range(16))

    # random plaintext
    length = random.randrange(10, 40)
    plaintext = ''.join(chr(random.randrange(256)) for _ in range(length))

    # random prefixindex
    prefixindex = random.randrange(length)

    cipher = AES.new(key, AES.MODE_ECB)

    def encfunc(prefix):
        padded = pad(plaintext[:prefixindex] + prefix + plaintext[prefixindex:], blocklen=16)
        return cipher.encrypt(padded)

    decipherable = aestools.ecb_chosenprefix(encfunc, prefixindex=prefixindex, blocklen=16)
    assert decipherable == plaintext[prefixindex:]


if __name__ == '__main__':

    for _ in range(10):
        test_cbc_findiv()
    print 'cbc_findiv test passed!'

    for _ in range(10):
        test_cbc_paddingoracle()
    print 'cbc_paddingoracle test passed!'

    for _ in range(10):
        test_ecb_chosenprefix()
    print 'ecb_chosenprefix test passed!'