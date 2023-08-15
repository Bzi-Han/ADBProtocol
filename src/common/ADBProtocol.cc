#include "ADBProtocol.h"

#include "ADBService.h"

std::optional<android::adb::PairingResult> android::adb::Pairing(const std::string_view &password, const std::string_view &ip, uint16_t port, const std::string_view &privateKeyString)
{
    auto &service = ADBService::GetInstance();

    auto pairingResult = service.Pairing(password, ip, port, privateKeyString);
    if (!pairingResult.has_value())
        return std::nullopt;

    return android::adb::PairingResult{pairingResult->privateKey, pairingResult->publicKey};
}

void android::adb::DisConnect(int deviceId)
{
    auto &service = ADBService::GetInstance();

    return service.DisConnect(deviceId);
}

int android::adb::Connect(const std::string_view &ip, uint16_t port, const std::string_view &privateKeyString)
{
    auto &service = ADBService::GetInstance();

    return service.Connect(ip, port, privateKeyString);
}

bool android::adb::Shell(int deviceId, const std::string_view &command)
{
    auto &service = ADBService::GetInstance();

    return service.Shell(deviceId, command);
}

void android::adb::Push(int deviceId, void *data, size_t dataLength, const std::filesystem::path &writeToPath)
{
    auto &service = ADBService::GetInstance();

    return service.Push(deviceId, data, dataLength, writeToPath);
}