unameOut="$(uname -s)"
case "${unameOut}" in
    Linux*)     PATH="$(pwd)/osxcross/target/bin:$PATH" CC=o64-clang CXX=o64-clang++ LIBZ_SYS_STATIC=1 cargo build --target x86_64-apple-darwin --release
                ;;
    Darwin*)    cargo build --target=x86_64-apple-darwin --release
                ;;
    *)          ;;
esac