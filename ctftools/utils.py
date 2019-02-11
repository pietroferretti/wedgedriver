# -*- coding: utf-8 -*-

# MIT License
#
# Copyright (c) 2017 Pietro Ferretti
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

from six import binary_type, int2byte, iterbytes, indexbytes
from six.moves import zip, zip_longest


def index1byte(bytearr, i):
    return int2byte(indexbytes(bytearr, i))


def xor(a, b):
    """Applies XOR to two byte arrays, truncated at the length of the shortest argument"""
    res = binary_type()
    for x, y in zip(iterbytes(a), iterbytes(b)):
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
