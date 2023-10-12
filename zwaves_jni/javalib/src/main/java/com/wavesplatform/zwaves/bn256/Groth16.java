package com.wavesplatform.zwaves.bn256;

public class Groth16 {
    public static native boolean verify(byte[] vk, byte[] proof, byte[] inputs);

    static {
        com.wavesplatform.zwaves.ZWavesJNILibrary.init();
    }
}
