# Java bindings for zwaves-jni rust library

First build libraries files for every platform using `../build...` scripts (from `zwaves_jni` working folder on every OS) and then place appropriate `libzwaves_jni.so`, `libzwaves_jni.dylib` and `libzwaves_jni.dll` files them to `./src/main/resources/META-INF/native/...` in appropriate folder.


Next build this project (from this working folder) with `gradle jar`, resulted jar file will be in `./build/libs/` folder.