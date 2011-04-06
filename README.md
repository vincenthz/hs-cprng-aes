CPRNG-AES
=========

This module provides a crypto pseudo random number generator using AES in counter mode.

to import:

    import Crypto.Random.AESCtr

to use:

    rng <- makeSystem
    let (ran, rng') = getRandomBytes rng 1024

it's also an instance of CryptoRandomGen from the crypto-api package.
