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

from six import binary_type, int2byte, iterbytes, indexbytes, unichr, PY3, next
from six.moves import zip, zip_longest
from itertools import cycle


def bytes2unic(bytearr):
    return ''.join(unichr(x) for x in iterbytes(bytearr))


def index_one_byte(bytearr, i):
    return int2byte(indexbytes(bytearr, i))


def iter_wrapper(iterated):
    """Returns bytes if iterating bytes, and iterates normally otherwise"""
    iterator = iter(iterated)
    if PY3 and isinstance(iterated, binary_type):
        while True:
            try:
                yield int2byte(next(iterator))
            except StopIteration:
                return
    else:
        while True:
            try:
                yield next(iterator)
            except StopIteration:
                return


def xor(text, key):
    """Applies XOR to two byte arrays, truncated at the length of the shortest argument"""
    res = binary_type()
    for x, y in zip(iterbytes(text), cycle(iterbytes(key))):
        res += int2byte(x ^ y)
    return res


def blockify(text, blocklen):
    """Splits data as a list of `blocklen`-long values"""
    return [text[i:i + blocklen] for i in range(0, len(text), blocklen)]


def columnify(ciphertext, keylen, fill=False):
    """Takes the ciphertext and groups the characters corresponding to each key index position.

    Arguments:
        ciphertext -- the ciphertext as a byte array (Python 3) / string (Python 2)
        keylen     -- the length of the xor key
        fill       -- if True all the lists of characters will 
                      be filled with None to have the same length (default False)

    Returns a list of lists of characters.
    """
    # split ciphertext in blocks
    blocks = blockify(ciphertext, keylen)
    # build list of lists
    result = [list(tup) for tup in zip_longest(*blocks)]
    # remove Nones
    if not fill:
        for l in result:
            if None in l:
                l.remove(None)  # at most one None
    return result


def egcd(a, b):
    """Computes the Euclidean Greatest Common Divisor"""
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y
