package com.wavesplatform.zwaves;

public class ZWavesJNILibrary {
    static {
        // Our layout: "META-INF/native/${platform}/${arch}/${library[-version]}"
        new JNILibrary("zwaves_jni", ZWavesJNILibrary.class).load();
    }

    public static void init() {}
}
