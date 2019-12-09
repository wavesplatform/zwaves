# JNI for groth16verify

## Build

To build `zwaves.jar` we need to cross compile the library for Linux, Windows and MacOS. 
This HOWTO is working for `rust 1.38+ stable` and Ubuntu 64bit.


### Install gradle

Install [gradle](https://gradle.org/install/).

### Install dependencies and add targets

```sh
# Install dependencies for cross compilation Linux to MacOS
apt install clang gcc g++ zlib1g-dev libmpc-dev libmpfr-dev libgmp-dev

# Install dependencies for cross compilation Linux to Windows
apt install mingw-w64

# Install dependencies for compilation 32bit binary
apt install gcc-multilib


# Add Rust targets

rustup target add x86_64-apple-darwin
rustup target add i686-pc-windows-gnu
rustup target add x86_64-pc-windows-gnu
rustup target add i686-unknown-linux-gnu
rustup target add x86_64-unknown-linux-gnu


```

### Build jar

```sh
# build jar file
./build_all.sh 
```

Get `zwaves.jar` from `javalib/build/libs/zwaves.jar`.