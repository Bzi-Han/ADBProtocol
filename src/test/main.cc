#include "ADBProtocol.h"

#include <iostream>
#include <string>

int main()
{
    std::string privateKey = R"()";
    std::string ip = "127.0.0.1";
    uint16_t port = 7555;

    auto deviceId = android::adb::Connect(ip, port, privateKey);
    if (-1 == deviceId)
    {
        std::cout << "Connect to %s:%p failed" << std::endl;
        return 1;
    }

    if (!android::adb::Shell(deviceId, "cmd notification post -S bigtext -t 'Hello ADB' 'ADBProtocol' 'This message is from ADBProtocol.'"))
    {
        std::cout << "Execute shell command failed" << std::endl;
        return 1;
    }

    std::cout << "You should see the notification on your device" << std::endl;
    getchar();

    return 0;
}