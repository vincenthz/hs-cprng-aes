-- |
-- Module      : Crypto.Random.AESCtr
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : unknown
--
-- this CPRNG is an AES based counter system.
--
-- the internal size of fields are: 16 bytes IV, 16 bytes counter, 32 bytes key
--
-- each block are generated the following way:
--   aes (IV `xor` counter) -> 16 bytes output
--
{-# LANGUAGE CPP #-}
{-# LANGUAGE BangPatterns #-}
module Crypto.Random.AESCtr
    ( AESRNG
    , make
    , makeSystem
    ) where

import Crypto.Random
import Crypto.Random.AESCtr.Internal
import Control.Arrow (second)

import Data.ByteString (ByteString)
import qualified Data.ByteString as B

import Data.Byteable
import Data.Bits (xor, (.&.))

-- | AES Counter mode Pseudo random generator.
--
-- Provide a very good Cryptographic pseudo random generator
-- that create pseudo random output based an AES cipher
-- used in counter mode, initialized from random key, random IV
-- and random nonce.
--
-- This CPRG uses 64 bytes of pure entropy to create its random state.
--
-- By default, this generator will automatically reseed after generating
-- 1 megabyte of data.
data AESRNG = AESRNG { aesrngState     :: RNG
                     , aesrngEntropy   :: EntropyPool
                     , aesrngThreshold :: Int -- ^ in number of generated block
                     , aesrngCache     :: ByteString }

instance Show AESRNG where
    show _ = "aesrng[..]"

makeFrom :: EntropyPool -> B.ByteString -> AESRNG
makeFrom entPool b = AESRNG
    { aesrngState        = rng
    , aesrngEntropy      = entPool
    , aesrngThreshold    = 1024 -- in blocks generated, so 1mb
    , aesrngCache        = B.empty }
  where rng = RNG entropy cnt 0 key
        (key, cnt, entropy) = makeParams b

-- | make an AES RNG from an EntropyPool.
--
-- use `makeSystem` to not have to deal with the entropy pool.
make :: EntropyPool -> AESRNG
make entPool = makeFrom entPool b
  where !b = toBytes $ grabEntropy 64 entPool

-- | Initialize a new AES RNG using the system entropy.
-- {-# DEPRECATED makeSystem "use cprgCreate with an entropy pool" #-}
makeSystem :: IO AESRNG
makeSystem = make `fmap` createEntropyPool

-- | get a Random number of bytes from the RNG.
-- it generate randomness by block of chunkSize bytes and will returns
-- a block bigger or equal to the size requested.
genRandomBytesState :: RNG -> Int -> (ByteString, RNG)
genRandomBytesState rng n
    | n <= chunkSize = genNextChunk rng
    | otherwise      = let (bs, rng') = acc 0 [] rng
                        in (B.concat bs, rng')
  where acc l bs g
            | l * chunkSize >= n = (bs, g)
            | otherwise          = let (b, g') = genNextChunk g
                                    in acc (l+1) (b:bs) g'

genRanBytesNoCheck :: AESRNG -> Int -> (ByteString, AESRNG)
genRanBytesNoCheck rng n
    | B.length (aesrngCache rng) >= n = let (b1,b2) = B.splitAt n (aesrngCache rng)
                                         in (b1, rng { aesrngCache = b2 })
    | otherwise                       =
        let (b, rng') = genRandomBytesState (aesrngState rng) n
            (b1, b2)  = B.splitAt n b
         in (b1, rng { aesrngState = rng', aesrngCache = b2 })

-- | generate a random set of bytes
genRanBytes :: AESRNG -> Int -> (ByteString, AESRNG)
genRanBytes rng n = second reseedThreshold $ genRanBytesNoCheck rng n

reseedThreshold :: AESRNG -> AESRNG
reseedThreshold rng
    | getNbChunksGenerated (aesrngState rng) >= lvl =
         let ent = toBytes $ grabEntropy 64 (aesrngEntropy rng)
          in rng { aesrngState = reseedState ent (aesrngState rng) }
    | otherwise  = rng
  where
        lvl = aesrngThreshold rng
        reseedState :: ByteString -> RNG -> RNG
        reseedState b g@(RNG _ cnt1 _ _) = RNG left cnt2 0 key2
            where -- (r16, _)           = genNextChunk g
                  (key2, cnt2, left) = makeParams b

instance CPRG AESRNG where
    cprgCreate                      = make
    cprgSetReseedThreshold lvl rng  = reseedThreshold (rng { aesrngThreshold = if nbChunks > 0 then nbChunks else 1 })
      where nbChunks = lvl `div` chunkSize
    cprgGenerate len rng            = genRanBytes rng len
    cprgGenerateWithEntropy len rng =
        let ent        = toBytes $ grabEntropy len (aesrngEntropy rng)
            (bs, rng') = genRanBytes rng len
         in (B.pack $ B.zipWith xor ent bs, rng')
    cprgFork rng = let (b,rng') = genRanBytes rng 64
                    in (rng', makeFrom (aesrngEntropy rng) b)

{-
instance RandomGen AESRNG where
    next rng =
        let (bs, rng') = genRanBytes rng 16 in
        let (Word128 a _) = get128 bs in
        let n = fromIntegral (a .&. 0x7fffffff) in
        (n, rng')
    split rng =
        let rng' = make (aesrngEntropy rng)
         in (rng, rng')
    genRange _ = (0, 0x7fffffff)
-}
