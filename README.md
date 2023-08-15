# ADBProtocol

#### 介绍

实现用于与Android无线调试(ADB WiFi)通信的C++库。

参考ADB官方项目：https://android.googlesource.com/platform/packages/modules/adb

#### 编译

0. 确保在项目根目录打开命令行终端 。
1. 执行`git submodule init` 。
2. 执行`git submodule update` 。
3. 执行`cmake -S . -B build`。
4. 执行`cmake --build build --config Release --target ALL_BUILD`。
5. 编译完成。

如果你的目标是Android平台，可以使用`build.bat`来进行批量编译，默认编译`armeabi-v7a arm64-v8a x86 x86_64`四个版本，可修改脚本中的`ANDROID_ABIS`变量来进行更改。

脚本有三个可选参数分别为：NDK路径、最低支持SDK版本、CMake程序路径，不设置则脚本自动检测`NDK_PATH`与CMake工具链，如果都没有则使用脚本默认内置路径。

#### 使用

如果你要单独使用，在编译后复制`modules/ADBProtocol.h`与静态库文件到项目目录里使用即可。

如果以git submodule的方式使用，在添加`add_subdirectory`后链接`ADBProtocol`即可。

例子请看：[src/test/main.cc](https://github.com/Bzi-Han/ADBProtocol/blob/main/src/test/main.cc)
