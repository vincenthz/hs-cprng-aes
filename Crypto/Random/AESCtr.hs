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
import System.Random (RandomGen(..))
import Crypto.Random.AESCtr.Internal

import Data.ByteString (ByteString)
import qualified Data.ByteString as B

import Data.Byteable
import Data.Bits (xor, (.&.))

data AESRNG = AESRNG { aesrngState   :: RNG
                     , aesrngEntropy :: EntropyPool
                     , aesrngEntropyLevel :: EntropyReseedLevel
                     , aesrngCache   :: ByteString }

instance Show AESRNG where
    show _ = "aesrng[..]"

makeFrom :: EntropyPool -> EntropyReseedLevel -> B.ByteString -> AESRNG
makeFrom entPool lvl b = AESRNG
    { aesrngState        = rng
    , aesrngEntropy      = entPool
    , aesrngEntropyLevel = lvl
    , aesrngCache        = B.empty }
  where rng            = RNG (get128 iv) (get128 cnt) 0 key
        (key, cnt, iv) = makeParams b

-- | make an AES RNG from a bytestring seed. the bytestring need to be at least 64 bytes.
-- if the bytestring is longer, the extra bytes will be ignored and will not take part in
-- the initialization.
--
-- use `makeSystem` to not have to deal with the generator seed.
make :: EntropyPool -> EntropyReseedLevel -> AESRNG
make entPool lvl = makeFrom entPool lvl b
  where !b = toBytes $ grabEntropy 64 entPool

-- | Initialize a new AES RNG using the system entropy.
-- {-# DEPRECATED makeSystem "use cprgCreate with an entropy pool" #-}
makeSystem :: IO AESRNG
makeSystem =
    createEntropyPool >>= \pool ->
    return $ make pool EntropyReseed_Normal

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
genRanBytes rng n =
    let r@(bs, rng') = genRanBytesNoCheck rng n in
    case aesrngEntropyLevel rng of
        EntropyReseed_None   -> r
        EntropyReseed_Normal -> (bs, reseedIf 1024 rng')
        EntropyReseed_High   -> (bs, reseedIf 16   rng')
  where reseedIf lvl g
            | getNbChunksGenerated (aesrngState g) >= lvl =
                 let ent = toBytes $ grabEntropy 64 (aesrngEntropy g)
                  in rng { aesrngState = reseedState ent (aesrngState g) }
            | otherwise  = g

        reseedState :: ByteString -> RNG -> RNG
        reseedState b g@(RNG _ cnt1 _ _) = RNG (get128 r16 `xor128` get128 iv2) (cnt1 `xor128` get128 cnt2) 0 key2
            where (r16, _)          = genNextChunk g
                  (key2, cnt2, iv2) = makeParams b

instance CPRG AESRNG where
    cprgCreate pool lvl             = make pool lvl
    cprgGenerate len rng            = genRanBytes rng len
    cprgGenerateWithEntropy len rng =
        let ent        = toBytes $ grabEntropy len (aesrngEntropy rng)
            (bs, rng') = genRanBytes rng len
         in (B.pack $ B.zipWith xor ent bs, rng')
    cprgFork lvl rng | lvl == EntropyReseed_None = let (b,rng') = genRanBytes rng 64
                                                    in (rng', makeFrom (aesrngEntropy rng) lvl b)
                     | otherwise                 = (rng, make (aesrngEntropy rng) lvl)

instance RandomGen AESRNG where
    next rng =
        let (bs, rng') = genRanBytes rng 16 in
        let (Word128 a _) = get128 bs in
        let n = fromIntegral (a .&. 0x7fffffff) in
        (n, rng')
    split rng =
        let rng' = make (aesrngEntropy rng) (aesrngEntropyLevel rng)
         in (rng, rng')
    genRange _ = (0, 0x7fffffff)
