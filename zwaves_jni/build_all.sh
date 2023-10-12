cargo build --target=i686-unknown-linux-gnu --release
cp ../target/i686-unknown-linux-gnu/release/libzwaves_jni.so javalib/src/main/resources/META-INF/native/linux32

cargo build --target=x86_64-unknown-linux-gnu --release
cp ../target/x86_64-unknown-linux-gnu/release/libzwaves_jni.so javalib/src/main/resources/META-INF/native/linux64

PATH="$(pwd)/osxcross/target/bin:$PATH" CC=o64-clang CXX=o64-clang++ LIBZ_SYS_STATIC=1 cargo build --target x86_64-apple-darwin --release
cp ../target/x86_64-apple-darwin/release/libzwaves_jni.dylib javalib/src/main/resources/META-INF/native/osx

cargo build --target=i686-pc-windows-gnu --release
cp ../target/i686-pc-windows-gnu/release/zwaves_jni.dll javalib/src/main/resources/META-INF/native/windows32

cargo build --target=x86_64-pc-windows-gnu --release
cp ../target/x86_64-pc-windows-gnu/release/zwaves_jni.dll javalib/src/main/resources/META-INF/native/windows64

pushd javalib
./gradlew build
popd