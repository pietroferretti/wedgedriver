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

from ctftools import rsatools

import pytest
import random
from Crypto.PublicKey import RSA

from six import binary_type, int2byte


def random_bytes(n):
    return binary_type().join(int2byte(random.randrange(256)) for _ in range(n))


def generate_RSA(bits=2048, e=65537):
    new_key = RSA.generate(bits, e=e)
    return new_key


@pytest.mark.parametrize('seed', range(10))
def test_rsa_encrypt_decrypt(seed):
    key = generate_RSA()
    e, d, n = key.e, key.d, key.n
    length = random.randrange(10, 255)
    plaintext = random_bytes(length)
    ciphertext = rsatools.rsa_encrypt(plaintext, e, n)
    assert rsatools.rsa_decrypt(ciphertext, d, n) == plaintext


@pytest.mark.parametrize('seed', range(10))
def test_rsa_known_factors(seed):
    key = generate_RSA()
    e, p, q, n = key.e, key.p, key.q, key.n
    length = random.randrange(10, 255)
    plaintext = random_bytes(length)
    ciphertext = rsatools.rsa_encrypt(plaintext, e, n)
    d = rsatools.rsa_find_private_from_factors(p, q, e)
    assert rsatools.rsa_decrypt(ciphertext, d, n) == plaintext


@pytest.mark.parametrize('seed', range(10))
def test_rsa_decrypt_cubic_root(seed):
    key = generate_RSA(e=3)
    e, n = key.e, key.n
    length = random.randrange(10, 80)   # 80 < 256 / 3
    plaintext = random_bytes(length)
    ciphertext = rsatools.rsa_encrypt(plaintext, e, n)
    assert rsatools.rsa_decrypt_root(ciphertext, e) == plaintext


# TODO test common primes
