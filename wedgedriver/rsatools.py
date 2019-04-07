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

# TODO
# low private exponent: wiener attack
# low public exponent: coppersmith theorem, hastad's broadcast attack, related messages

from pkgutil import iter_modules
from six import iterbytes, binary_type, int2byte

from .utils import egcd


def module_exists(module_name):
    return module_name in (name for loader, name, ispkg in iter_modules())


def phi(p, q):
    return (p - 1) * (q - 1)


def modinv(a, m):
    """Returns the modular inverse of a modulo m"""
    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError('The modular inverse does not exist')
    else:
        return x % m


def compute_root(n, r, precision=300):
    """Compute the r-th root of n"""
    if not module_exists('gmpy'):
        raise ImportError("`compute_root` needs the gmpy module to work!")
    import gmpy
    gmpy.set_minprec(precision)
    m = gmpy.mpz(n)
    root, exact = gmpy.root(m, r)
    if not exact:
        raise ValueError("No exact root found, maybe try increasing the precision?")
    return int(root)


def binary_to_num(binarr):
    res = 0
    for byte in iterbytes(binarr):
        res = res << 8
        res += byte
    return res


def num_to_binary(number):
    res = binary_type()
    while number > 0:
        res += int2byte(number & 0xff)
        number = number >> 8
    return res[::-1]


def rsa_encrypt(plaintext, e, n):
    """Encrypt the plaintext with textbook RSA (no padding) with public exponent *e* and modulus *n*"""
    plain_int = binary_to_num(plaintext)
    cipher_int = pow(plain_int, e, n)
    return num_to_binary(cipher_int)


def rsa_decrypt(ciphertext, d, n):
    """Decrypt the plaintext with textbook RSA (no padding) with private exponent *d* and modulus *n*"""
    return rsa_encrypt(ciphertext, d, n)    # encryption and decryption are equivalent


def rsa_decrypt_crt(ciphertext, p, q, dp, dq):
    """Decrypt a ciphertext using the optimized Chinese Remainder Theorem version of RSA"""
    c = binary_to_num(ciphertext)
    if q > p:    # p deve essere > di q
        p, q = q, p
        dp, dq = dq, dp
    m1 = pow(c, dp, p)
    m2 = pow(c, dq, q)
    qinv = modinv(q, p)
    h = (qinv * (m1 - m2)) % p    # FIXME case when m1 < m2?
    m = m2 + h*q
    return num_to_binary(m)


def rsa_decrypt_root(ciphertext, r, precision=300):
    """Decrypt a ciphertext obtained by applying a RSA encryption with small public exponent *r* on a small message"""
    cipher_int = binary_to_num(ciphertext)
    plain_int = compute_root(cipher_int, r, precision=precision)
    return num_to_binary(plain_int)


def rsa_find_private_from_factors(p, q, e):
    """Find the private exponent from the modulus' factors and the public exponent"""
    return modinv(e, phi(p, q))


def rsa_find_common_primes(moduli):
    """Factorize a number of RSA moduli by looking for common factors
    (assumes the moduli are of type p * q, with p and q prime)
    Returns a dictionary mapping modulus -> [factors found]"""
    res = {}
    while moduli:
        n = moduli.pop()
        for m in moduli:
            # try all combinations at least once, without breaking
            p, _, _ = egcd(n, m)
            if p != 1:
                if n not in res:
                    res[n] = (p, n/p)
                if m not in res:
                    res[m] = (p, m/p)
        if n not in res:
            res[n] = (n, 1)
    return res
