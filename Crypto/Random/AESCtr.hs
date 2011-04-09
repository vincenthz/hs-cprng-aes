-- |
-- Module      : Crypto.Random.AESCtr
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : unknown
--
-- this CPRNG is an AES cbc based counter system.
--
-- the internal size of fields are: 16 bytes IV, 16 bytes counter, 32 bytes key
--
-- each block are generated the following way:
--   (IV `xor` counter) `aes` key -> 16 bytes output
--

module Crypto.Random.AESCtr
	( AESRNG
	, make
	, makeSystem
	, genRandomBytes
	) where

import Control.Applicative ((<$>))

import Crypto.Random
import System.Crypto.Random (getEntropy)
import qualified Crypto.Cipher.AES as AES

import Data.ByteString (ByteString)
import qualified Data.ByteString as B

import Data.Word
import Data.Bits (xor)
import Data.Serialize

data Word128 = Word128 !Word64 !Word64

{-| An opaque object containing an AES CPRNG -}
data AESRNG = RNG !ByteString !Word128 !AES.Key

instance Show AESRNG where
	show _ = "aesrng[..]"

put128 :: Word128 -> ByteString
put128 (Word128 a b) = runPut (putWord64host a >> putWord64host b)

get128 :: ByteString -> Word128
get128 = either (\_ -> Word128 0 0) id . runGet (getWord64host >>= \a -> (getWord64host >>= \b -> return $ Word128 a b))

add1 :: Word128 -> Word128
add1 (Word128 a b) = if b == 0xffffffffffffffff then Word128 (a+1) 0 else Word128 a (b+1)

makeParams :: ByteString -> (AES.Key, ByteString, ByteString)
makeParams b = (key, cnt, iv)
	where
		(Right key)  = AES.initKey256 $ B.take 32 left2
		(cnt, left2) = B.splitAt 16 left1
		(iv, left1)  = B.splitAt 16 b

-- | make an AESRNG from a bytestring. the bytestring need to be at least 64 bytes.
-- if the bytestring is longer, the extra bytes will be ignored and will not take part in
-- the initialization.
make :: B.ByteString -> Either GenError AESRNG
make b
	| B.length b < 64 = Left NotEnoughEntropy
	| otherwise       = Right $ RNG iv (get128 cnt) key
		where
			(key, cnt, iv) = makeParams b

chunkSize :: Int
chunkSize = 16

bxor :: ByteString -> ByteString -> ByteString
bxor a b = B.pack $ B.zipWith xor a b

nextChunk :: AESRNG -> (ByteString, AESRNG)
nextChunk (RNG iv counter key) = (chunk, newrng)
	where
		newrng = RNG chunk (add1 counter) key
		chunk  = AES.encryptCBC key iv bytes
		bytes  = iv `bxor` (put128 counter)

-- | Initialize a new AESRng using the system entropy.
makeSystem :: IO AESRNG
makeSystem = ofRight . make <$> getEntropy 64
	where
		ofRight (Left _)  = error "ofRight on a Left value"
		ofRight (Right x) = x

-- | get a Random number of bytes from the RNG.
-- for efficienty and not wasted any randomness, it's better to generate
-- bytes on multiple of 16, however it will works for any size.
genRandomBytes :: AESRNG -> Int -> (ByteString, AESRNG)
genRandomBytes rng n =
	let list = helper rng n in
	(B.concat $ map fst list, snd $ last list)
	where
		helper _ 0 = []
		helper g i =
			let (b, g') = nextChunk g in
			if chunkSize >= i
				then [ (B.take i b, g') ]
				else (b, g') : helper g' (i-chunkSize)

instance CryptoRandomGen AESRNG where
	newGen           = make
	genSeedLength    = 64
	genBytes len rng = Right $ genRandomBytes rng len
	reseed b rng@(RNG _ cnt1 _)
		| B.length b < 64 = Left NotEnoughEntropy
		| otherwise       = Right $ RNG (r16 `bxor` iv2) (get128 (put128 cnt1 `bxor` cnt2)) key2
			where
				(r16, _)          = nextChunk rng
				(key2, cnt2, iv2) = makeParams b