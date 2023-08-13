#ifndef ADB_SERVICE_H // !ADB_SERVICE_H
#define ADB_SERVICE_H

#include "ADBProtoImpl.h"

#include <yasio/yasio/yasio.hpp>

#include <string>
#include <string_view>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <functional>
#include <mutex>
#include <condition_variable>

class ADBService
{
public:
    struct DeviceInfo
    {
        uint32_t id;
        std::string infoString;
        std::string_view name;
        std::string_view model;
        std::string_view device;
        std::unordered_set<std::string_view> features;
        yasio::inet::transport_handle_t transport;
    };

public:
    static ADBService &GetInstance()
    {
        static ADBService service;

        return service;
    }

public:
    int Connect(const std::string_view &ip = "", uint16_t port = 0);

    void DisConnect(int deviceId);

    void Shell(int deviceId, const std::string_view &command);

    void Push(int deviceId);

    DeviceInfo &operator[](uint32_t index)
    {
        return m_deviceInfos[index];
    }

private:
    ADBService();
    ~ADBService();

    std::vector<std::string_view> StringSplitAsciiView(const std::string_view &str, const std::string_view &delimiter);

    void OnADBMessage(uint32_t id, yasio::inet::transport_handle_t transport);

private:
    PacketStream m_packetStream;
    ADBMessageData m_messageData;

    yasio::io_service m_service;
    std::unordered_map<ADBCommand, std::function<void(bool result, uint32_t id, yasio::inet::transport_handle_t transport)>> m_eventCallbacks;
    std::mutex m_eventMutex;
    std::condition_variable m_eventCondition;
    std::unordered_map<uint32_t, DeviceInfo> m_deviceInfos;
};

#endif // !ADB_SERVICE_H