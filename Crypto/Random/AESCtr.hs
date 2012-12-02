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
{-# LANGUAGE CPP, PackageImports #-}
module Crypto.Random.AESCtr
    ( AESRNG
    , make
    , makeSystem
    , genRandomBytes
    ) where

import Control.Applicative ((<$>))

import Crypto.Random
import System.Random (RandomGen(..))
import System.Entropy (getEntropy)
#ifdef CIPHER_AES
import qualified "cipher-aes" Crypto.Cipher.AES as AES
#else
import qualified "cryptocipher" Crypto.Cipher.AES as AES
#endif

import Data.ByteString (ByteString)
import qualified Data.ByteString as B

import Data.Word
import Data.Bits (xor, (.&.))

#ifdef USE_CEREAL
import Data.Serialize
#else
import Foreign.Ptr
import Foreign.ForeignPtr.Unsafe (unsafeForeignPtrToPtr)
import Foreign.Storable
import qualified Data.ByteString.Internal as B
#endif

data Word128 = Word128 {-# UNPACK #-} !Word64 {-# UNPACK #-} !Word64

{-| An opaque object containing an AES CPRNG -}
data RNG = RNG
    {-# UNPACK #-} !Word128
    {-# UNPACK #-} !Word128
    {-# UNPACK #-} !AES.Key

data AESRNG = AESRNG { aesrngState :: RNG
                     , aesrngCache :: ByteString }

instance Show AESRNG where
    show _ = "aesrng[..]"

-- using serialize to grab a w128 as a non-negligeable cost,
-- the Bytestring pointer manipulation are much faster.
#if USE_CEREAL

put128 :: Word128 -> ByteString
put128 (Word128 a b) = runPut (putWord64host a >> putWord64host b)

get128 :: ByteString -> Word128
get128 = either (\_ -> Word128 0 0) id . runGet (getWord64host >>= \a -> (getWord64host >>= \b -> return $ Word128 a b))

#else

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
#endif

xor128 :: Word128 -> Word128 -> Word128
xor128 (Word128 a1 b1) (Word128 a2 b2) = Word128 (a1 `xor` a2) (b1 `xor` b2)

#ifdef CIPHER_AES
add64 :: Word128 -> Word128
add64 (Word128 a b) = if b >= (0xffffffffffffffff-63) then Word128 (a+1) (b+64) else Word128 a (b+64)
#else
add1 :: Word128 -> Word128
add1 (Word128 a b) = if b == 0xffffffffffffffff then Word128 (a+1) 0 else Word128 a (b+1)
#endif

makeParams :: ByteString -> (AES.Key, ByteString, ByteString)
makeParams b = (key, cnt, iv)
    where
#ifdef CIPHER_AES
        key          = AES.initKey $ B.take 32 left2
#else
        (Right key)  = AES.initKey256 $ B.take 32 left2
#endif
        (cnt, left2) = B.splitAt 16 left1
        (iv, left1)  = B.splitAt 16 b

-- | make an AES RNG from a bytestring seed. the bytestring need to be at least 64 bytes.
-- if the bytestring is longer, the extra bytes will be ignored and will not take part in
-- the initialization.
--
-- use `makeSystem` to not have to deal with the generator seed.
make :: B.ByteString -> Either GenError AESRNG
make b
    | B.length b < 64 = Left NotEnoughEntropy
    | otherwise       = Right $ AESRNG { aesrngState = rng, aesrngCache = B.empty }
        where
            rng            = RNG (get128 iv) (get128 cnt) key
            (key, cnt, iv) = makeParams b

#ifdef CIPHER_AES
chunkSize :: Int
chunkSize = 1024

genNextChunk :: RNG -> (ByteString, RNG)
genNextChunk (RNG iv counter key) = (chunk, newrng)
    where
        newrng = RNG (get128 chunk) (add64 counter) key
        chunk  = AES.genCTR key (AES.IV bytes) 1024
        bytes  = put128 (iv `xor128` counter)
#else
chunkSize :: Int
chunkSize = 16

genNextChunk :: RNG -> (ByteString, RNG)
genNextChunk (RNG iv counter key) = (chunk, newrng)
    where
        newrng = RNG (get128 chunk) (add1 counter) key
        chunk  = AES.encrypt key bytes
        bytes  = put128 (iv `xor128` counter)
#endif

-- | Initialize a new AES RNG using the system entropy.
makeSystem :: IO AESRNG
makeSystem = ofRight . make <$> getEntropy 64
    where
        ofRight (Left _)  = error "ofRight on a Left value"
        ofRight (Right x) = x

-- | get a Random number of bytes from the RNG.
-- it generate randomness by block of chunkSize bytes and will returns
-- a block bigger or equal to the size requested.
genRandomBytesState :: RNG -> Int -> (ByteString, RNG)
genRandomBytesState rng n
    | n <= chunkSize = genNextChunk rng
    | otherwise      = let (bs, rng') = acc 0 [] rng
                        in (B.concat bs, rng')
    where
        acc l bs g
            | l * chunkSize >= n = (bs, g)
            | otherwise          = let (b, g') = genNextChunk g
                                    in acc (l+1) (b:bs) g'

genRandomBytes :: AESRNG -> Int -> (ByteString, AESRNG)
genRandomBytes rng n
    | B.length (aesrngCache rng) >= n = let (b1,b2) = B.splitAt n (aesrngCache rng)
                                         in (b1, rng { aesrngCache = b2 })
    | otherwise                       =
            let (b, rng') = genRandomBytesState (aesrngState rng) n
                (b1, b2)  = B.splitAt n b
             in (b1, rng { aesrngState = rng', aesrngCache = b2 })

reseedState b rng@(RNG _ cnt1 _) = RNG (get128 r16 `xor128` get128 iv2) (cnt1 `xor128` get128 cnt2) key2
    where (r16, _)          = genNextChunk rng
          (key2, cnt2, iv2) = makeParams b

instance CryptoRandomGen AESRNG where
    newGen           = make
    genSeedLength    = 64
    genBytes len rng = Right $ genRandomBytes rng len
    reseed b rng
        | B.length b < 64 = Left NotEnoughEntropy
        | otherwise       = Right $ rng { aesrngState = reseedState b (aesrngState rng) }

instance RandomGen AESRNG where
    next rng =
        let (bs, rng') = genRandomBytes rng 16 in
        let (Word128 a _) = get128 bs in
        let n = fromIntegral (a .&. 0x7fffffff) in
        (n, rng')
    split rng =
        let (bs, rng') = genRandomBytes rng 64 in
        case make bs of
            Left _      -> error "assert"
            Right rng'' -> (rng', rng'')
    genRange _ = (0, 0x7fffffff)
