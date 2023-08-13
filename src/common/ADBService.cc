#include "ADBService.h"

#include <iostream>
#include "HexDump.h"
#include "sslcerts.hpp"

struct yssl_options
{
    char *crtfile_;
    char *keyfile_;
    bool client;
};

extern yssl_ctx_st *yssl_ctx_new(const yssl_options &opts);
extern void yssl_ctx_free(yssl_ctx_st *&ctx);

extern yssl_st *yssl_new(yssl_ctx_st *ctx, int fd, const char *hostname, bool client);
extern void yssl_shutdown(yssl_st *&, bool writable);

extern int yssl_do_handshake(yssl_st *ssl, int &err);
extern const char *yssl_strerror(yssl_st *ssl, int sslerr, char *buf, size_t buflen);

ADBService::ADBService()
    : m_service({"127.0.0.1", 7555})
{
    // C:\Users\Bzi_Han\.android\adbkey
    // m_service.set_option(yasio::YOPT_S_SSL_CACERT, "C:\\Users\\Bzi_Han\\.android\\adbkey.pub");

    m_service.set_option(yasio::YOPT_C_UNPACK_PARAMS, 0, 10 * 1024 * 1024, offsetof(ADBMessage::Header, dataLength), 4, sizeof(ADBMessage::Header));
    m_service.set_option(yasio::YOPT_C_UNPACK_NO_BSWAP, 0, 1);
    m_service.set_option(yasio::YOPT_S_TCP_KEEPALIVE, 5, 10, 2);
    m_service.start(
        [&](yasio::event_ptr &&ev)
        {
            switch (ev->kind())
            {
            case yasio::YEK_ON_OPEN:
            {
                if (0 == ev->status())
                {
                    // Connect message
                    m_messageData.FillMessage(ADBCommand::CNXN, "host::features=shell_v2,cmd,stat_v2,ls_v2,fixed_push_mkdir,apex,abb,fixed_push_symlink_timestamp,abb_exec,remount_shell,track_app,sendrecv_v2,sendrecv_v2_brotli,sendrecv_v2_lz4,sendrecv_v2_zstd,sendrecv_v2_dry_run_send,openscreen_mdns");
                    m_messageData.header.param1 = 0x1000001;
                    m_messageData.header.param2 = 0x100000;
                    m_packetStream << m_messageData;

                    m_service.write(ev->transport(), m_packetStream.Buffer().data(), m_packetStream.Buffer().size());
                }
                else if (m_eventCallbacks.contains(ADBCommand::CNXN))
                {
                    m_eventCallbacks[ADBCommand::CNXN](false, ev->source_id(), ev->transport());
                    m_eventCallbacks.erase(ADBCommand::CNXN);
                }

                break;
            }
            case yasio::YEK_ON_CLOSE:
            {
                if (m_deviceInfos.contains(ev->source_id()))
                    m_deviceInfos.erase(ev->source_id());
                break;
            }
            case yasio::YEK_ON_PACKET:
            {
                if (ev->packet().size() < sizeof(ADBMessage::Header))
                    break;

                m_packetStream.Clear();
                m_packetStream << ev->packet();
                m_packetStream.Seek(0);
                m_packetStream >> m_messageData;

                OnADBMessage(ev->source_id(), ev->transport());
                break;
            }
            default:
                break;
            }
        });
}

ADBService::~ADBService()
{
    m_service.close(0);
    m_service.stop();
}

std::vector<std::string_view> ADBService::StringSplitAsciiView(const std::string_view &str, const std::string_view &delimiter)
{
    std::vector<std::string_view> result;

    size_t pos = 0, lastPos = 0;
    while (std::string::npos != (pos = str.find(delimiter, lastPos)))
    {
        result.emplace_back(str.data() + lastPos, pos - lastPos);
        lastPos = pos + delimiter.length();
    }

    result.emplace_back(str.data() + lastPos, str.length() - lastPos);

    return result;
}

void ADBService::OnADBMessage(uint32_t id, yasio::inet::transport_handle_t transport)
{
    std::cout << "<<=====================================================================" << std::endl;
    std::cout << "message.header.command: " << std::hex << static_cast<uint32_t>(m_messageData.header.command) << std::dec << std::endl;
    std::cout << "message.header.param1: " << std::hex << m_messageData.header.param1 << std::endl;
    std::cout << "message.header.param2: " << std::hex << m_messageData.header.param2 << std::endl;

    switch (m_messageData.header.command)
    {
    case ADBCommand::CNXN:
    {
        std::cout << "Connect to device successfully" << std::endl;
        break;
    }
    case ADBCommand::OKAY:
        std::cout << "Command execute succeeded" << std::endl;
        break;
    case ADBCommand::WRTE:
        std::cout << "Command return data" << std::endl;
        HexDump::print(m_messageData.data, m_messageData.header.dataLength);
        break;
    case ADBCommand::CLSE:
        std::cout << "Command execute all done" << std::endl;
        break;
    case ADBCommand::STLS:
    {
        std::cout << "Handshake failed, need perform TLS handshake" << std::endl;

        std::cout << "begin stls:" << m_service.write(transport, m_packetStream.Buffer().data(), m_packetStream.Buffer().size()) << std::endl;

        static auto saveTransport = transport;
        std::thread(
            [&]
            {
                auto sslContext = yssl_ctx_new(
                    yssl_options{
                        .crtfile_ = const_cast<char *>("C:\\Users\\Bzi_Han\\Desktop\\AndroidLocalADB\\test.crt"),
                        .keyfile_ = const_cast<char *>("C:\\Users\\Bzi_Han\\.android\\adbkey"),
                        .client = true,
                    });
                std::cout << "sslContext:" << sslContext << std::endl;
                std::cout << "nativeHandle:" << static_cast<int>(saveTransport->socket_->native_handle()) << std::endl;
                auto sslInstance = yssl_new(sslContext, static_cast<int>(saveTransport->socket_->native_handle()), "wtf", true);
                std::cout << "sslInstance:" << sslInstance << std::endl;

                int err = 0;
                char errMsg[1024]{};
                std::cout << "do handshake:" << yssl_do_handshake(sslInstance, err) << std::endl;
                std::cout << "error:" << yssl_strerror(sslInstance, err, errMsg, 1024) << std::endl;

                getchar();
                std::cout << "cleanup" << std::endl;

                yssl_shutdown(sslInstance, true);
                yssl_ctx_free(sslContext);
            })
            .detach();
    }
    default:
        break;
    }

    if (m_eventCallbacks.contains(m_messageData.header.command))
    {
        m_eventCallbacks[m_messageData.header.command](true, id, transport);
        m_eventCallbacks.erase(m_messageData.header.command);
    }
}

int ADBService::Connect(const std::string_view &ip, uint16_t port)
{
    if (!ip.empty() && 0 != port)
        m_service.set_option(yasio::YOPT_C_REMOTE_ENDPOINT, 0, ip.data(), port);

    int deviceId = -1;

    m_eventCallbacks.insert(
        {
            ADBCommand::CNXN,
            [&](bool result, uint32_t id, yasio::inet::transport_handle_t transport)
            {
                if (!result)
                {
                    m_eventCondition.notify_one();
                    return;
                }

                m_deviceInfos.insert(
                    {
                        id,
                        {
                            .id = id,
                            .infoString = {m_messageData.data, m_messageData.header.dataLength},
                            .transport = transport,
                        },
                    });
                auto &device = m_deviceInfos[id];

                auto deviceInfo = StringSplitAsciiView(device.infoString, "::");
                if (deviceInfo.size() < 2 || "device" != deviceInfo[0])
                {
                    m_eventCondition.notify_one();
                    return;
                }

                deviceInfo = StringSplitAsciiView(deviceInfo[1], ";");
                if (deviceInfo.size() < 3)
                {
                    m_eventCondition.notify_one();
                    return;
                }

                for (const auto &property : deviceInfo)
                {
                    auto propertyInfo = StringSplitAsciiView(property, "=");

                    if ("ro.product.name" == propertyInfo[0])
                        device.name = propertyInfo[1];
                    else if ("ro.product.model" == propertyInfo[0])
                        device.model = propertyInfo[1];
                    else if ("ro.product.device" == propertyInfo[0])
                        device.device = propertyInfo[1];
                    else if ("features" == propertyInfo[0])
                    {
                        for (const auto &feature : StringSplitAsciiView(propertyInfo[1], ","))
                            device.features.insert(feature);
                    }
                }

                deviceId = id;
                m_eventCondition.notify_one();
            },
        });
    m_service.open(0, yasio::YCK_TCP_CLIENT);
    {
        std::unique_lock<std::mutex> locker(m_eventMutex);

        m_eventCondition.wait(locker);
    }

    return deviceId;
}

void ADBService::DisConnect(int deviceId)
{
    m_service.close(0);

    if (m_deviceInfos.contains(deviceId))
        m_deviceInfos.erase(deviceId);
}

void ADBService::Shell(int deviceId, const std::string_view &command)
{
    if (!m_deviceInfos.contains(deviceId))
        return;

    std::string shellCommand = "shell,v2,TERM=xterm-256color,raw:";
    shellCommand.append(command);

    m_messageData.FillMessage(ADBCommand::OPEN, "");
    m_messageData.header.param1 = 0x45;
    m_messageData.header.param2 = 0x0;
    m_messageData.header.dataLength = static_cast<uint32_t>(shellCommand.length());
    m_messageData.data = const_cast<char *>(shellCommand.data());
    m_packetStream.Clear();
    m_packetStream << m_messageData;

    m_service.write(m_deviceInfos[deviceId].transport, m_packetStream.Buffer().data(), m_packetStream.Buffer().size());
}

void ADBService::Push(int deviceId)
{
}