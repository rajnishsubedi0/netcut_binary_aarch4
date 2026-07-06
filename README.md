
# About this 

Compile executable netcut binary for Android device (aarch64). It uses libc.

### Preparation

Add target device

```bash
rustup target add aarch64-linux-android
```
### Can add following device if needed : (Optional)
```bash
rustup target add armv7-linux-androideabi
rustup target add x86_64-linux-android
```
    
### Environment Variables

Export following environment variable on terminal. Android studio NDK is used as environment variable so dont need to download other files.


```bash
export ANDROID_NDK_HOME="/home/rkant/Android/Sdk/ndk/28.2.13676358"
export TOOLCHAIN="/home/rkant/Android/Sdk/ndk/28.2.13676358/toolchains/llvm/prebuilt/linux-x86_64"
export PATH="$TOOLCHAIN/bin:$PATH"
```


### Compile

Compile the code with following command with target device

```bash
  cargo build --release --target aarch64-linux-android
```



Output executable binary will be on `./target/aarch64-linux-android/release` folder.



### Runing the binary, needs root.

```
./netcut -i wlan0 -g 192.168.18.1 -t 192.168.18.54
```

```-i``` flag is interface of the network. Type ```ifconfig``` or ```iwconfig``` on terminal to get network interface. ```-g``` flag is gateway of the router ```(Admin gateway)```).  ```-t``` flag is ip address of targeted user. To target multiple client we can use ```-t 192.168.18.54,192.168.18.152,192.168.18.78```.


