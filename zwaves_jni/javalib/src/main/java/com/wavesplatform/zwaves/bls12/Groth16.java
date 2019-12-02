package com.wavesplatform.zwaves.bls12;

public class Groth16 {
    public static native boolean verify(byte[] vk, byte[] proof, byte[] inputs);
}