module Main where

import Criterion.Main

import qualified Data.ByteString as B
import Crypto.Random.AESCtr

gen rng n = fst (genRandomBytes rng n)

main = makeSystem >>= \rng -> defaultMain
    [ bgroup "generate random bytes"
        [ bench "1"    $ nf (gen rng) 1
        , bench "8"    $ nf (gen rng) 8
        , bench "16"   $ nf (gen rng) 16
        , bench "256"  $ nf (gen rng) 256
        , bench "1024" $ nf (gen rng) 1024
        , bench "4096" $ nf (gen rng) 4096
        ]
    ]
