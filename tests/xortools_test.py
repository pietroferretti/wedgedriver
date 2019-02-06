#!/usr/bin/env python2
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

from ctftools import xortools
from ctftools.utils import xor

import pytest
import random

from six import int2byte, byte2int, binary_type, indexbytes, iterbytes, b
from six.moves import range


PLAINTEXTS = ['''Class ended in five minutes and all I could think was, an hour is too long for lunch.
Since the start of the semester, I had been looking forward to the part of Mr. Gladly's World Issues class where we'd start discussing capes.  Now that it had finally arrived, I couldn't focus.  I fidgeted, my pen moving from hand to hand, tapping, or absently drawing some figure in the corner of the page to join the other doodles.  My eyes were restless too, darting from the clock above the door to Mr. Gladly and back to the clock.  I wasn't picking up enough of his lesson to follow along.  Twenty minutes to twelve; five minutes left before class ended.''',
'''The Empire stands triumphant.
For twenty years the Dread Empress has ruled over the lands that were once the Kingdom of Callow, but behind the scenes of this dawning golden age threats to the crown are rising. The nobles of the Wasteland, denied the power they crave, weave their plots behind pleasant smiles. In the north the Forever King eyes the ever-expanding borders of the Empire and ponders war. The greatest danger lies to the west, where the First Prince of Procer has finally claimed her throne: her people sundered, she wonders if a crusade might not be the way to secure her reign. Yet none of this matters, for in the heart of the conquered lands the most dangerous man alive sat across an orphan girl and offered her a knife. ''',
'''In cryptography, a substitution cipher is a method of encrypting by which units of plaintext are replaced with ciphertext, according to a fixed system; the "units" may be single letters (the most common), pairs of letters, triplets of letters, mixtures of the above, and so forth. The receiver deciphers the text by performing the inverse substitution.
Substitution ciphers can be compared with transposition ciphers. In a transposition cipher, the units of the plaintext are rearranged in a different and usually quite complex order, but the units themselves are left unchanged. By contrast, in a substitution cipher, the units of the plaintext are retained in the same sequence in the ciphertext, but the units themselves are altered. ''']


def random_bytes(n):
    return binary_type().join(int2byte(random.randrange(256)) for _ in range(n))


@pytest.mark.parametrize('seed', range(10))
def test_xor_repeated_key_known_length(seed):
    random.seed(seed)

    # choose a random length
    length = random.randrange(5, 20)
    # choose a random key
    key = random_bytes(length)
    for text in PLAINTEXTS:
        plaintext = b(text)
        # encrypt with xor
        ciphertext = xor(plaintext, key*(len(plaintext) // len(key) + 1))
        # decrypt
        my_key = xortools.findkey(ciphertext, keylen=length, decfunc=xor)
        my_plain = xor(ciphertext, my_key*(len(plaintext) // len(key) + 1))
        assert plaintext == my_plain


# TODO
# find key length automatically

# TODO
# some other polyalphabetic substitution cipher

# TODO
# key in plaintext

