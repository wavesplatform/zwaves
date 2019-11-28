package com.wavesplatform.zwaves;

public class Groth16 {
    public static native boolean verify(byte[] vk, byte[] proof, byte[] inputs);
}