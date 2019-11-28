package com.wavesplatform.zwaves;

public class Bls12PedersenMerkleTree {
    public static native byte[] addItem(byte[] sibling, long index, byte[] leaf);
}