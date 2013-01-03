module Main where

import Criterion.Main

import qualified Data.ByteString as B
import Crypto.Random.AESCtr
import System.IO.Unsafe (unsafePerformIO)
import Data.IORef

gen rng n = fst (genRandomBytes n rng)

gen2 rngref n = unsafePerformIO $ do
    rng <- readIORef rngref
    let (b, rng2) = genRandomBytes n rng
    writeIORef rngref rng2
    return b

main = do
    rng <- makeSystem
    rngref <- newIORef rng

    defaultMain
        [ bgroup "generate random bytes (init)"
            [ bench "1"    $ nf (gen rng) 1
            , bench "8"    $ nf (gen rng) 8
            , bench "16"   $ nf (gen rng) 16
            , bench "256"  $ nf (gen rng) 256
            , bench "1024" $ nf (gen rng) 1024
            , bench "4096" $ nf (gen rng) 4096
            ]
        , bgroup "generate random bytes (continous)"
            [ bench "1"    $ nf (gen2 rngref) 1
            , bench "8"    $ nf (gen2 rngref) 8
            , bench "16"   $ nf (gen2 rngref) 16
            , bench "256"  $ nf (gen2 rngref) 256
            , bench "1024" $ nf (gen2 rngref) 1024
            , bench "4096" $ nf (gen2 rngref) 4096
            ]
        ]
