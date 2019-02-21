#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# MIT License
#
# Copyright (c) 2019 Pietro Ferretti
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from ctftools import aestools

import pytest
import random
from Crypto.Cipher import AES

from six import int2byte, binary_type, indexbytes, iterbytes
from six.moves import range


class BadPaddingError(Exception):
    """Used to implement a padding oracle"""
    pass


def pad(s, blocklen):
    if blocklen > 256:
        return ValueError('The block length must be less than 256!')
    remainder = len(s) % blocklen
    if remainder == 0:
        return s + int2byte(blocklen) * blocklen
    else:
        return s + int2byte(blocklen - remainder) * (blocklen - remainder)


def is_padding_ok(s, blocklen):
    padvalue = indexbytes(s, -1)
    if padvalue > blocklen:
        return False
    return all(c == padvalue for c in iterbytes(s[-padvalue:]))


def unpad(s, blocklen):
    if not is_padding_ok(s, blocklen):
        raise BadPaddingError()
    padvalue = indexbytes(s, -1)
    return s[:-padvalue]


def random_bytes(n):
    return binary_type().join(int2byte(random.randrange(256)) for _ in range(n))


@pytest.mark.parametrize('seed', range(100))
def test_cbc_findiv(seed):
    random.seed(seed)

    # random 128 bits IV, key
    IV = random_bytes(16)
    key = random_bytes(16)

    def decfunc(ciphertext):
        cipher = AES.new(key, AES.MODE_CBC, IV=IV)
        return cipher.decrypt(ciphertext)

    assert aestools.cbc_findiv(decfunc, blocklen=16) == IV


@pytest.mark.parametrize('seed', range(100))
def test_cbc_paddingoracle(seed):
    random.seed(seed)

    # random 128 bits IV, key
    IV = random_bytes(16)
    key = random_bytes(16)

    # random plaintext
    length = random.randrange(10, 40)
    plaintext = random_bytes(length)

    cipher = AES.new(key, AES.MODE_CBC, IV=IV)
    ciphertext = IV + cipher.encrypt(pad(plaintext, blocklen=16))

    def oraclefunc(ciphertext):
        cipher_dec = AES.new(key, AES.MODE_CBC, IV=IV)
        return is_padding_ok(cipher_dec.decrypt(ciphertext), blocklen=16)

    res = aestools.cbc_paddingoracle(ciphertext, oraclefunc, blocklen=16)
    assert res == pad(plaintext, blocklen=16)


@pytest.mark.parametrize('seed', range(100))
def test_ecb_chosenprefix(seed):
    random.seed(seed)
    # random 128 bits key
    key = random_bytes(16)

    # random plaintext
    length = random.randrange(10, 40)
    plaintext = random_bytes(length)

    # random prefixindex
    prefixindex = random.randrange(length)

    def encfunc(prefix):
        cipher = AES.new(key, AES.MODE_ECB)
        padded = pad(plaintext[:prefixindex] + prefix + plaintext[prefixindex:], blocklen=16)
        return cipher.encrypt(padded)

    decipherable = aestools.ecb_chosenprefix(encfunc, prefixindex=prefixindex, blocklen=16)
    assert decipherable == plaintext[prefixindex:] or unpad(decipherable, 16) == plaintext[prefixindex:]
