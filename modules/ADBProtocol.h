#ifndef ADB_PROTOCOL_H // !ADB_PROTOCOL_H
#define ADB_PROTOCOL_H

#include <string>
#include <string_view>
#include <optional>
#include <filesystem>

namespace android
{
    namespace adb
    {
        struct PairingResult
        {
            std::string privateKey;
            std::string publicKey;
        };

        std::optional<PairingResult> Pairing(const std::string_view &password, const std::string_view &ip = "127.0.0.1", uint16_t port = 7555, const std::string_view &privateKeyString = "");

        void DisConnect(int deviceId);

        int Connect(const std::string_view &ip = "127.0.0.1", uint16_t port = 7555, const std::string_view &privateKeyString = "");

        bool Shell(int deviceId, const std::string_view &command);

        void Push(int deviceId, void *data, size_t dataLength, const std::filesystem::path &writeToPath = "/data/local/tmp/temp");
    }
}

#endif // !ADB_PROTOCOL_H