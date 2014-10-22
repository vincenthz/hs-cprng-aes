-- |
-- Module      : Crypto.Random.AESCtr.Internal
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : unknown
--
{-# LANGUAGE CPP #-}
{-# LANGUAGE BangPatterns #-}
module Crypto.Random.AESCtr.Internal where

import qualified Crypto.Cipher.AES as AES

import Data.ByteString (ByteString)
import qualified Data.ByteString as B

{-| An opaque object containing an AES CPRNG -}
data RNG = RNG
    {-# UNPACK #-} !ByteString -- left over entropy. can be use to reseed
    {-# UNPACK #-} !AES.AESIV  -- counter
    {-# UNPACK #-} !Int        -- number of chunks generated since reseed
    {-# UNPACK #-} !AES.AES    -- AES context

getNbChunksGenerated :: RNG -> Int
getNbChunksGenerated (RNG _ _ c _) = c

makeParams :: ByteString -> (AES.AES, AES.AESIV, ByteString)
makeParams b = key `seq` entropy `seq` (key, AES.aesIV_ cnt, entropy)
  where (keyBS, r1) = B.splitAt 32 b
        (cnt, r2)   = B.splitAt 16 r1
        !entropy    = B.copy r2
        !key        = AES.initAES keyBS

chunkSize :: Int
chunkSize = 1024

genNextChunk :: RNG -> (ByteString, RNG)
genNextChunk (RNG entropy counter nbChunks key) = (chunk, newrng)
  where
        newrng = RNG entropy newCounter (nbChunks+1) key
        (chunk,newCounter) = AES.genCounter key counter chunkSize
