package com.wavesplatform.zwaves.bls12;

public class PedersenMerkleTree {
    public static native byte[] addItem(byte[] root, byte[] sibling, long index, byte[] leaf);
}