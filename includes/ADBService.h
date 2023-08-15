#ifndef ADB_SERVICE_H // !ADB_SERVICE_H
#define ADB_SERVICE_H

#include "ADBProtoStructImpl.h"
#include "GoogleFunctional.h"
#include "Log.h"

#include <yasio/yasio/xxsocket.hpp>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/curve25519.h>

#include <string>
#include <string_view>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <functional>
#include <mutex>
#include <condition_variable>
#include <random>
#include <numeric>
#include <future>
#include <filesystem>
#include <optional>

class ADBService
{
public:
    struct NetworkContext
    {
        size_t id;
        std::unique_ptr<yasio::xxsocket> transport;

        SSL_CTX *sslContext;
        SSL *sslInstance;
        std::string privateKey;

        bool syncMode;
        bool isWritePacketCompletion;
        std::vector<char> writePacketCompletionBuffer;

        struct Hash
        {
            std::size_t operator()(const NetworkContext &context) const noexcept
            {
                return std::hash<size_t>{}(context.id);
            }
        };

        struct EqualTo
        {
            bool operator()(const NetworkContext &left, const NetworkContext &right) const noexcept
            {
                return left.id == right.id;
            }
        };

        NetworkContext(std::unique_ptr<yasio::xxsocket> &&socketTransport, const std::string_view &privateKeyString = "")
            : transport(std::move(socketTransport)),
              sslContext(nullptr),
              sslInstance(nullptr),
              privateKey(privateKeyString.begin(), privateKeyString.end()),
              syncMode(false),
              isWritePacketCompletion(true),
              writePacketCompletionBuffer()
        {
            static size_t networkContextId = 0;

            id = networkContextId++;
        }
    };

    struct DeviceInfo
    {
        size_t id;
        std::string infoString;
        std::string_view name;
        std::string_view model;
        std::string_view device;
        std::unordered_set<std::string_view> features;
        const NetworkContext *networkContext;
    };

    struct PairingResult
    {
        std::string privateKey;
        std::string publicKey;
    };

public:
    static ADBService &GetInstance()
    {
        static ADBService service;

        return service;
    }

public:
    std::optional<PairingResult> Pairing(const std::string_view &password, const std::string_view &ip = "127.0.0.1", uint16_t port = 7555, const std::string_view &privateKeyString = "");

    int Connect(const std::string_view &ip = "127.0.0.1", uint16_t port = 7555, const std::string_view &privateKeyString = "");

    void DisConnect(int deviceId);

    bool Shell(int deviceId, const std::string_view &command);

    void Push(int deviceId, void *data, size_t dataLength, const std::filesystem::path &writeToPath = "/data/local/tmp/temp");

    DeviceInfo &operator[](uint32_t index)
    {
        return m_deviceInfos[index];
    }

private:
    ADBService();
    ~ADBService();

    uint32_t RandomNumber() const;

    std::vector<std::string_view> StringSplitAsciiView(const std::string_view &str, const std::string_view &delimiter);

    int ReadData(const NetworkContext &context, void *buffer, size_t bufferLength);

    int SendData(const NetworkContext &context, void *data, size_t dataLength);

    bool DoTlsHandshake(NetworkContext &context);

    void OnADBMessage(const NetworkContext &context);

private:
    size_t m_maxReadPacketSize = 1 * 1024 * 1024;
    PacketStream m_readPacketStream, m_writePacketStream;
    ADBMessageData m_readMessageData, m_writeMessageData;

    bool m_work = false;
    std::mutex m_networkContextsMutex;
    std::unordered_set<NetworkContext, NetworkContext::Hash, NetworkContext::EqualTo> m_networkContexts;
    std::unique_ptr<std::thread> m_networkThread;

    std::unordered_map<size_t, std::unordered_map<ADBCommand, std::function<void(bool state, const NetworkContext &context)>>> m_eventCallbacks;
    std::unordered_map<size_t, DeviceInfo> m_deviceInfos;
};

#endif // !ADB_SERVICE_H