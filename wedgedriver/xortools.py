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

import itertools
import pkg_resources
from itertools import cycle
from six import iterbytes, int2byte, next, binary_type, b
from six.moves import range, filter

from .utils import xor, egcd, blockify, columnify, index_one_byte, bytes2unic, iter_wrapper
from .loggers import LOGGER


LETTERS = b('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz')
DIGITS = b('0123456789')
PUNCTUATION = b('!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~')
PRINTABLE = LETTERS + DIGITS + PUNCTUATION + b(' \t\n\r\x0b\x0c')

with open(pkg_resources.resource_filename('wedgedriver', 'data/english_words.txt')) as f:
    ENGLISH_DICTIONARY = set(f.read().split('\n'))
ENGLISH_DISTRIBUTION = {b'a': 8.167, b'b': 1.492, b'c': 2.782, b'd': 4.253, b'e': 12.702, b'f': 2.228, b'g': 2.015,
                        b'h': 6.094, b'i': 6.966, b'j': 0.153, b'k': 0.772, b'l': 4.025, b'm': 2.406, b'n': 6.749,
                        b'o': 7.507, b'p': 1.929, b'q': 0.095, b'r': 5.987, b's': 6.327, b't': 9.056, b'u': 2.758,
                        b'v': 0.978, b'w': 2.360, b'x': 0.150, b'y': 1.974, b'z': 0.074}


def hamming_distance(a, b):
    """Returns the Hamming Distance between two byte arrays of equal length."""
    assert len(a) == len(b)
    distance = 0
    for byte1, byte2 in zip(iterbytes(a), iterbytes(b)):
        diff = byte1 ^ byte2
        distance += sum((diff >> i) & 1 for i in range(8))
    return distance


def englishscore(text):
    """Estimates how close the distribution of characters in a string is to english text.

    Returns the score for the text as a number (higher is better).
    """
    score = 0

    # raise or decrease score based on the type of characters present
    # arbitrary scores, could be better
    for c in iterbytes(text):
        c = int2byte(c)
        if c in LETTERS:
            score += 1
        elif c == b' ':
            score += 0.8
        elif c in DIGITS:
            score += 0.5
        elif c in PUNCTUATION:
            score += 0.2
        elif c not in PRINTABLE:
            score -= 10

    # next, do some frequency analysis to compare strings with the same number of letters
    # we will only use the letters
    text_letters = binary_type().join(int2byte(c) for c in filter(lambda c: int2byte(c) in LETTERS, iterbytes(text)))
    text_letters = text_letters.lower()
    if len(text_letters) > 0:
        # normalize
        totalsum = sum(ENGLISH_DISTRIBUTION.values())
        distribution = {}
        for letter in ENGLISH_DISTRIBUTION:
            distribution[letter] = ENGLISH_DISTRIBUTION[letter] / totalsum

        # compute distribution for every character
        textlen = len(text_letters)
        textdist = {}
        for x in iterbytes(text_letters):
            x = int2byte(x)
            if x in textdist:
                textdist[x] += 1.0 / textlen
            else:
                textdist[x] = 1.0 / textlen

        # compute Pearson chi-squared statistic
        chi2 = 0
        for c in distribution:
            p = distribution[c]
            obs = textdist.get(c, 0)
            chi2 += ((obs - p) ** 2) / p
        chi2 = chi2 * textlen

        # normalize to avoid giving the frequency analysis too much importance
        if chi2 <= 1:
            bonus = 1
        else:
            bonus = 1.0 / chi2
        score += bonus

    return score


def dictionary_score(text):
    """Give points for full english words"""
    score = 0
    text_words = binary_type()
    for c in iterbytes(text):
        byte = int2byte(c)
        if byte in LETTERS:
            text_words += byte
        else:
            text_words += b(' ')
    words = text_words.split(b(' '))
    for word in words:
        if len(word) >= 5 and bytes2unic(word) in ENGLISH_DICTIONARY:
            score += len(word)
    return score


def findkeylen_all(ciphertext, maxcompperlen=1000000):
    """Determines the length of a repeated xor key given a ciphertext.

    The algorithm works using the Normalized Hamming Distance.

    Arguments:
        ciphertext    -- the ciphertext as a byte array
        maxcompperlen -- the maximum number of comparisons between blocks that will be performed for each candidate length

    Returns all the possible key lengths and their respective score as a list of (length, score) tuples.
    The list is ordered from the best to the worst score (lower is better).
    """

    len_score_list = []

    # try every useful length
    for keylen in range(1, len(ciphertext) // 2 + 1):
        LOGGER.info('Checking key length {}'.format(keylen))

        # split in blocks
        blocks = blockify(ciphertext, keylen)

        # keep only full-length blocks 
        blocks = filter(lambda b: len(b) == keylen, blocks)

        # get hamming distance of each block with every other block
        total_distance = 0
        n_comparisons = 0
        for block1, block2 in itertools.combinations(blocks, 2):
            total_distance += hamming_distance(block1, block2)
            n_comparisons += 1
            if n_comparisons >= maxcompperlen:
                break

        avg_distance = float(total_distance) / n_comparisons
        norm_distance = avg_distance / keylen

        len_score_list.append((keylen, norm_distance))

    # order by ascending score
    result = sorted(len_score_list, key=(lambda t: t[1]))
    return result


def findkeylen(ciphertext, topn=17, maxcompperlen=100):
    """Determines the length of a repeated xor key given a ciphertext.

    Takes the greatest common divisor of the most probable candidates, because multiples of the actual key length often get better scores.
    (see also https://trustedsignal.blogspot.it/2015/06/xord-play-normalized-hamming-distance.html)
    NB: this works best when the characters of the key are very different from one another.

    Arguments:
        ciphertext    -- the ciphertext as a byte array
        topn          -- the number of candidate lengths to consider in the gcd step
        maxcompperlen -- the maximum number of comparisons between blocks that will be performed for each candidate length

    Returns the most probable key length.
    """

    LOGGER.info('Collecting key length candidates...')
    len_score_list = findkeylen_all(ciphertext, maxcompperlen=maxcompperlen)
    topn_lengths = [t[0] for t in len_score_list[:topn]]

    LOGGER.info('Computing most common gcd...')
    gcd_occurences = {}
    for len1, len2 in itertools.combinations(topn_lengths, 2):
        gcd = egcd(len1, len2)[0]
        if gcd != 1:
            if gcd not in gcd_occurences:
                gcd_occurences[gcd] = 1
            else:
                gcd_occurences[gcd] += 1

    # return most common gcd
    return max(gcd_occurences.keys(), key=(lambda k: gcd_occurences[k]))


def findkeychars(ciphertext, keylen, charset=PRINTABLE, decfunc=xor):
    """Finds all possible characters for each key index given a set of characters that can appear in the plaintext.

    This function assumes a polyalphabetic substition cipher is used.

    Arguments:
        ciphertext -- the ciphertext as a byte array
        charset    -- a string containing all the characters that can be found in the plaintext (default: all printable characters)
        keylen     -- the length of the key (default: found using findkeylen)
        decfunc    -- a function that takes a character of ciphertext and a character of key and returns a character of plaintext (default: xor)
    Returns a list of lists of characters, one list for each key index.
    """

    columns = columnify(ciphertext, keylen)

    LOGGER.info('Finding acceptable character sets...')
    result = []
    i = 1
    for column in columns:
        LOGGER.info('Checking column ' + str(i))
        # list of acceptable values for this key index
        good_chars = [int2byte(x) for x in range(256)]
        for elem in iter_wrapper(column):
            # find values of key that map to an acceptable plaintext
            ok_set = [int2byte(k) for k in range(256) if (decfunc([elem], int2byte(k)) in charset)]
            # take intersection with previous acceptable values
            good_chars = filter((lambda e: e in ok_set), good_chars)

        # order good_chars by closeness to the english character distribution
        LOGGER.info('Sorting characters by score...')

        def fitnessfunc(k):
            dec = binary_type().join(decfunc([elem], k) for elem in iter_wrapper(column))
            return englishscore(dec)
        best_char = sorted(good_chars, key=fitnessfunc)[::-1]

        LOGGER.info(best_char)
        result.append(best_char)
        i += 1

    LOGGER.info('Done finding acceptable key characters.')
    return result


def findkeys(ciphertext, keylen=None, charset=PRINTABLE, decfunc=xor):
    """Finds all possible keys given a set of characters that can appear in the ciphertext.

    This function assumes a substition cipher is used. (char by char)

    Arguments:
        ciphertext -- the ciphertext as a byte array
        charset    -- a string containing all the characters that can be found in the plaintext (default: all printable characters)
        keylen     -- the length of the key (default: found using findkeylen)
        decfunc    -- a function that takes a character of ciphertext and a character of key and returns a character of plaintext (default: xor)

    Returns a generator that yields keys as strings.
    """

    if keylen is None:
        LOGGER.info('Finding key length...')
        keylen = findkeylen(ciphertext)
        LOGGER.info('Key length = {}'.format(keylen))

    char_list = findkeychars(ciphertext, keylen, charset, decfunc)

    def key_generator(iter_prod):
        while True:
            try:
                yield binary_type().join(next(iter_prod))
            except StopIteration:
                return

    # extract first 100 keys, give priority to plaintexts with english words
    def generator_wrapper(key_gen):
        best_candidates = []
        for _ in range(100):
            try:
                best_candidates.append(next(key_gen))
            except StopIteration:
                break

        def candidate_score(key):
            return dictionary_score(decfunc(ciphertext, key))
        best_candidates.sort(key=candidate_score)

        while best_candidates:
            try:
                yield best_candidates.pop()
            except StopIteration:
                return
        while True:
            try:
                yield next(key_gen)
            except StopIteration:
                return

    # return key_generator(itertools.product(*char_list))
    return generator_wrapper(key_generator(itertools.product(*char_list)))


def findkey(ciphertext, keylen=None, charset=PRINTABLE, decfunc=xor):
    """A wrapper to get the first, most probable key from findkeys()"""
    try:
        result = next(findkeys(ciphertext, keylen, charset, decfunc))
        LOGGER.info('Key: {}'.format(result))
    except StopIteration:
        result = None
        LOGGER.info("No key found!")
    return result


def keyinplaintext(ciphertext, keylen, keyindex, seed, seedindex, decfunc=xor, keyfunc=None):
    """Solves the case when the key used to encrypt is embedded in the plaintext itself.

    This function assumes a polyalphabetic substition cipher is used.

    Arguments:
        ciphertext -- the ciphertext as a byte array
        keylen     -- the key length
        keyindex   -- the position of the key in the plaintext
        seed       -- a single known character in the plaintext
        seedindex  -- the position of the seed in the plaintext
        decfunc    -- a function that takes a character of ciphertext and a character of key, and returns a character of plaintext (default: xor)
        keyfunc    -- a function that takes a character of ciphertext and a character of plaintext, and returns a character of key (default: same as decfunc)

    Returns the  key.
    """

    if egcd(keyindex, keylen)[0] != 1:
        raise ValueError(
            "Impossible to solve.")

    # initial parameters
    if keyfunc is None:
        keyfunc = decfunc
    key = [None] * keylen
    key[seedindex % keylen] = keyfunc(index_one_byte(ciphertext, seedindex), seed)

    # iterate to find all the characters in the key
    for _ in range(keylen):
        newkey = key[:]
        for i in range(len(key)):
            if key[i] is not None:
                newkey[(i + keyindex) % keylen] = decfunc(index_one_byte(ciphertext, keyindex + i), key[i])
                print(newkey)
        key = newkey[:]

    print(key)
    assert None not in key

    return binary_type().join(key)


def make_decfunc(encfunc):
    """TODO docs and tests"""
    # generate lookup table
    lookup_table = {}
    for plain_i in range(256):
        plain_char = int2byte(plain_i)
        for key_i in range(256):
            key_char = int2byte(key_i)
            cipher_char = encfunc(plain_char, key_char)
            if cipher_char not in lookup_table:
                lookup_table[(cipher_char, key_char)] = plain_char

    def decfunc(ciphertext, key):
        res = binary_type()
        for c, k in zip(ciphertext, cycle(iterbytes(key))):
            res += lookup_table.get((c, int2byte(k)), b('\xff'))
        return res

    return decfunc
