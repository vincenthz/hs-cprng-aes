-- |
-- Module      : Crypto.Random.AESCtr.Internal
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : unknown
--
{-# LANGUAGE CPP #-}
module Crypto.Random.AESCtr.Internal where

import qualified Crypto.Cipher.AES as AES

import Data.ByteString (ByteString)
import qualified Data.ByteString as B

import Data.Word
import Data.Bits (xor)

import Foreign.Ptr
#if __GLASGOW_HASKELL__ > 704
import Foreign.ForeignPtr.Unsafe (unsafeForeignPtrToPtr)
#else
import Foreign.ForeignPtr (unsafeForeignPtrToPtr)
#endif

import Foreign.Storable
import qualified Data.ByteString.Internal as B

data Word128 = Word128 {-# UNPACK #-} !Word64 {-# UNPACK #-} !Word64

{-| An opaque object containing an AES CPRNG -}
data RNG = RNG
    {-# UNPACK #-} !Word128 -- nonce
    {-# UNPACK #-} !Word128 -- cnt
    {-# UNPACK #-} !Int     -- number of chunks generated since reseed
    {-# UNPACK #-} !AES.AES -- AES context

getNbChunksGenerated :: RNG -> Int
getNbChunksGenerated (RNG _ _ c _) = c

put128 :: Word128 -> ByteString
put128 (Word128 a b) = B.unsafeCreate 16 (write64 . castPtr)
    where write64 :: Ptr Word64 -> IO ()
          write64 ptr = poke ptr a >> poke (ptr `plusPtr` 8) b

get128 :: ByteString -> Word128
get128 (B.PS ps s _) = B.inlinePerformIO $ do
    let ptr = castPtr (unsafeForeignPtrToPtr ps `plusPtr` s) :: Ptr Word64
    a <- peek ptr
    b <- peek (ptr `plusPtr` 8)
    return $ Word128 a b

xor128 :: Word128 -> Word128 -> Word128
xor128 (Word128 a1 b1) (Word128 a2 b2) = Word128 (a1 `xor` a2) (b1 `xor` b2)

add64 :: Word128 -> Word128
add64 (Word128 a b) = if nb < 64 then Word128 (a+1) nb else Word128 a nb
  where nb = b + 64

{-
withBsPtr :: ByteString -> (Ptr Word8 -> IO a) -> IO a
withBsPtr (B.PS ps s _) f = withForeignPtr ps $ \ptr -> f (ptr `plusPtr` s)
-}

makeParams :: ByteString -> (AES.AES, ByteString, ByteString)
makeParams b = (key, cnt, nonce)
    where
        key            = AES.initAES $ B.take 32 left2
        (cnt, left2)   = B.splitAt 16 left1
        (nonce, left1) = B.splitAt 16 b

chunkSize :: Int
chunkSize = 1024

genNextChunk :: RNG -> (ByteString, RNG)
genNextChunk (RNG nonce counter nbChunks key) = (chunk, newrng)
  where
        newrng = RNG nonce (add64 counter) (nbChunks+1) key
        chunk  = AES.genCTR key bytes chunkSize
        bytes  = put128 (nonce `xor128` counter)
