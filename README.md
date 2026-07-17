
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
### For main.rs binary. It only supports one device

```
./netcut -i wlan0 --target 192.168.18.53 --gateway 192.168.18.1
```

```-i``` flag is interface of the network. Type ```ifconfig``` or ```iwconfig``` on terminal to get network interface. ```--gateway``` flag is gateway of the router ```(Admin gateway)```).  ```--target``` flag is ip address of targeted user. To target multiple client we can use ```--target 192.168.18.54,192.168.18.152,192.168.18.78```.


### For main2.rs binary. It only supports multiple devices built into the binary.

```bash
./netcut wlan0 192.168.18.1
```
After running this command the binary expects below commands.

```add <ip>``` To add the new device.

```remove <ip>``` To remove added device and restore the internet.

```list``` Show all the targeted devices.

```status``` Show service status and target count

```quit``` / ```exit``` To stop the service and restore the internet.



