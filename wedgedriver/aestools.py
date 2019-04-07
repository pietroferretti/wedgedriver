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

import binascii
from six import int2byte, binary_type, indexbytes
from six.moves import range

from .utils import xor, blockify
from .loggers import LOGGER


def cbc_flipiv(oldplain, newplain, iv):
    """Modifies an IV to produce the desired new plaintext in the following block"""
    flipmask = xor(oldplain, newplain)
    return xor(iv, flipmask)


def cbc_findiv(decfunc, blocklen=16, ciphblock=None):
    """Finds the IV used during an AES CBC decryption if it's not included in the ciphertext.

    This is useful if the IV is fixed but unknown, or even better if the IV is used as key.

    Arguments:
        decfunc   -- a decryption oracle function. The function must take a ciphertext (without the IV!) and return the decrypted plaintext
        blocklen  -- the block length (default: 16)
        ciphblock -- a specific ciphertext block to use in the decryption step (default: int2byte(ord('A'))*blocklen)

    Returns the IV used for the decryption.
    """

    if ciphblock:
        if len(ciphblock) != blocklen:
            raise ValueError('The ciphertext block must be as long as a block!')
    else:
        ciphblock = int2byte(ord('A')) * blocklen

    ciphertext = ciphblock + int2byte(0x00) * blocklen + ciphblock
    plaintext = decfunc(ciphertext)
    block1, _, block3 = blockify(plaintext, blocklen)  # block1 is P1, block3 is (P1 xor IV)
    iv = xor(block1, block3)
    return iv


def cbc_paddingoracle(ciphertext, oraclefunc, blocklen=16):
    """An implementation of the padding oracle attack against AES CBC.

    NB: The algorithm assumes PKCS#7 padding.

    Arguments:
        ciphertext -- the complete ciphertext, IV included
        oraclefunc -- a padding oracle function. The function must take a ciphertext as a string and return True if the padding is correct, False otherwise
        blocklen   -- the AES block length (default: 16)

    Returns the decrypted plaintext.
    """

    if len(ciphertext) % blocklen != 0:
        raise ValueError('The length of the ciphertext is not a multiple of the block length!')

    if len(ciphertext) < blocklen * 2:
        raise ValueError('The ciphertext is too short! (it must at least contain the IV block and another block)')

    plaintext = binary_type()

    # continue until we decrypted all useful blocks
    while len(ciphertext) >= blocklen * 2:

        # decrypted last block
        plainblock = binary_type()

        for i in range(1, blocklen + 1):
            found = []
            for guess in range(256):
                # take next to last block
                newblock = ciphertext[(-2 * blocklen):-blocklen]
                # try to null out the decrypted last block
                newblock = xor(newblock, (int2byte(guess) + plainblock).rjust(blocklen))
                # the result should be padded correctly
                newblock = xor(newblock, (int2byte(i) * i).rjust(blocklen))
                # if the padding is correct
                if oraclefunc(ciphertext[:(-2 * blocklen)] + newblock + ciphertext[-blocklen:]):
                    # add guess to possible candidates
                    found.append(guess)

            # spurious results can be found if the previous character is between 0x1 and 0x10
            # check which guess is wrong by changing the previous character
            good_guess = None
            if i != blocklen:
                for guess in found:
                    newblock = ciphertext[(-2 * blocklen):-blocklen]
                    newblock = xor(newblock, (int2byte(0x80) + int2byte(guess) + plainblock).rjust(blocklen))
                    newblock = xor(newblock, (int2byte(i) * i).rjust(blocklen))
                    if oraclefunc(ciphertext[:(-2 * blocklen)] + newblock + ciphertext[-blocklen:]):
                        good_guess = guess
                        break
            else:
                # there shouldn't be any spurious results for the last byte
                assert len(found) == 1
                good_guess = found[0]

            if good_guess is None:
                raise AssertionError('Something went wrong.')

            # update known plaintext
            plainblock = int2byte(good_guess) + plainblock

            LOGGER.info('Block {}, index {}'.format(len(plaintext) // blocklen, i))
            LOGGER.info(binascii.hexlify(plainblock))

        # update plaintext
        plaintext = plainblock + plaintext

        LOGGER.info('Result so far:')
        LOGGER.info(plaintext)

        # remove last block and repeat
        ciphertext = ciphertext[:-blocklen]

    return plaintext


def ecb_chosenprefix(encfunc, prefixindex=0, blocklen=16):
    """An implementation of the chosen prefix attack against AES ECB.

    This attack assumes that the attacker can insert an arbitrary string in the plaintext, and has access to an oracle encryption function which can provide the corresponding ciphertext.
    NB: the attack can only decrypt the plaintext that follows the prefix.

    Arguments:
        encfunc     -- an encryption oracle function. It must take as argument the prefix (as a string), and return the ciphertext corresponding to the plaintext with the prefix inserted
        prefixindex -- position where the prefix will be inserted in the ciphertext (default: 0)
        blocklen    -- the AES block length (default: 16)

    Returns the decrypted plaintext (the part after prefixindex).
    """

    # initial values
    my_pad = int2byte(ord('A'))
    plaintext = binary_type()
    ciphertext = encfunc(binary_type())

    if prefixindex >= len(ciphertext):
        return binary_type()

    prefixblock = prefixindex // blocklen
    indexinblock = prefixindex % blocklen

    # Part 1: block where the prefix starts

    # for each character in the prefix block after prefixindex
    for i in range(blocklen - indexinblock):

        # get ciphertext block containing a prefix we know and the next missing character
        prefix = my_pad * (blocklen - indexinblock - 1 - i)
        newciphertext = encfunc(prefix)
        newblock = newciphertext[(prefixblock * blocklen):((prefixblock + 1) * blocklen)]

        # try to guess the missing character
        for guess in range(256):
            prefix = my_pad * (blocklen - indexinblock - 1 - i) + plaintext + int2byte(guess)
            guessciphertext = encfunc(prefix)
            guessblock = guessciphertext[(prefixblock * blocklen):((prefixblock + 1) * blocklen)]
            if guessblock == newblock:
                plaintext += int2byte(guess)
                break

        # check if the plaintext has grown accordingly
        if (len(plaintext) - 1) != i:
            # if it didn't we probably hit the padding at the end and we should stop
            if prefixblock == len(ciphertext) / blocklen - 1 and indexbytes(plaintext, -1) == 0x01:
                LOGGER.info("Padding hit, we're done.")
                plaintext = plaintext[:-1]
                break
            else:
                raise AssertionError('Something went wrong.')

        LOGGER.info('Block {}, index {}'.format(prefixblock, indexinblock + i))
        LOGGER.info(plaintext)

    # Part 2: following blocks

    # for each block after the prefixblock
    for blockindex in range(prefixblock + 1, len(ciphertext) // blocklen):

        # for each character in the block
        for i in range(blocklen):

            # get ciphertext block containing a prefix we know and the next missing character
            prefix = my_pad * (blocklen - 1 - i)
            newciphertext = encfunc(prefix)
            newblock = newciphertext[(blockindex * blocklen):((blockindex + 1) * blocklen)]

            # try to guess the missing character
            for guess in range(256):
                prefix = my_pad * (blocklen - 1 - i) + plaintext + int2byte(guess)
                guessciphertext = encfunc(prefix)
                guessblock = guessciphertext[(blockindex * blocklen):((blockindex + 1) * blocklen)]
                if guessblock == newblock:
                    plaintext += int2byte(guess)
                    break

            # check if the plaintext has grown accordingly
            if (len(plaintext) + prefixindex - 1) % blocklen != i:
                # if it didn't we probably hit the padding at the end and we should stop
                if blockindex == len(ciphertext) / blocklen - 1 and indexbytes(plaintext, -1) == 0x01:
                    LOGGER.info("Padding hit, we're done.")
                    plaintext = plaintext[:-1]
                    break
                else:
                    raise AssertionError('Something went wrong.')

            LOGGER.info('Block {}, index {}'.format(blockindex, i))
            LOGGER.info(plaintext)

    return plaintext
