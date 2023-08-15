#include "ADBService.h"
#include "Log.h"

#include <iostream>
#include <string>

int main()
{
    auto &service = ADBService::GetInstance();

    // Pairing
    std::string password = "195346";
    std::string ip = "192.168.3.100";
    uint16_t port = 37749;
    auto pairingResult = service.Pairing(password, ip, port);
    if (!pairingResult.has_value())
    {
        LogFailed("Unable to pairing server %s:%d", ip.data(), port);
        return 1;
    }

    // Connect
    port = 40669;
    auto deviceId = service.Connect(ip, port, pairingResult->privateKey);
    if (-1 == deviceId)
    {
        LogFailed("Unable to connect server %s:%d", ip.data(), port);
        return 1;
    }

    // Command adb shell
    if (!service.Shell(deviceId, "cmd notification post -S bigtext -t 'Hello ADB' 'ADBProtocol' 'This message is from ADBProtocol.'"))
    {
        LogFailed("Execute shell command failed");
        return 1;
    }

    // Print device info
    LogInfo("device(%d) info:", deviceId);
    LogInfo("    id:%zd", service[deviceId].id);
    LogInfo("    infoString:%s", service[deviceId].infoString.data());
    LogInfo("    name:%s", std::string{service[deviceId].name.data(), service[deviceId].name.size()}.data());
    LogInfo("    model:%s", std::string{service[deviceId].model.data(), service[deviceId].model.size()}.data());
    LogInfo("    device:%s", std::string{service[deviceId].device.data(), service[deviceId].device.size()}.data());
    LogInfo("    features:");
    for (const auto &feature : service[deviceId].features)
        LogInfo("        %s", std::string{feature.data(), feature.size()}.data());

    getchar();

    return 0;
}