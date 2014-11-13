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
data RNG = RNG !AES.AESIV !Int !AES.AES

getNbChunksGenerated :: RNG -> Int
getNbChunksGenerated (RNG _ c _) = c

makeParams :: ByteString -> (AES.AES, AES.AESIV)
makeParams b = key `seq` iv `seq` (key, iv)
  where (keyBS, r1) = B.splitAt 32 b
        (cnt, _)    = B.splitAt 16 r1
        !key        = AES.initAES keyBS
        !iv         = AES.aesIV_ $ B.copy cnt

makeRNG :: ByteString -> RNG
makeRNG b = RNG iv 0 key
  where (key,iv) = makeParams b

chunkSize :: Int
chunkSize = 1024

genNextChunk :: RNG -> (ByteString, RNG)
genNextChunk (RNG counter nbChunks key) =
    chunk `seq` newrng `seq` (chunk, newrng)
  where
        newrng = RNG newCounter (nbChunks+1) key
        (chunk,newCounter) = AES.genCounter key counter chunkSize
