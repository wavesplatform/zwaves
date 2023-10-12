package com.wavesplatform.zwaves;

public class ZWavesJNILibrary {
    static {
        new JNILibrary("zwaves_jni", ZWavesJNILibrary.class).load();
    }

    public static void init() {}
}
