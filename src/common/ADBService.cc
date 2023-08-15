#include "ADBService.h"

ADBService::ADBService()
{
    m_readPacketStream.Reserve(m_maxReadPacketSize); // 1MB

    m_work = true;
    m_networkThread = std::make_unique<std::thread>(
        [&]
        {
            std::vector<const NetworkContext *> removeList;

            while (m_work)
            {
                if (!removeList.empty())
                {
                    for (auto contextPointer : removeList)
                    {
                        if (nullptr != contextPointer->sslInstance)
                            SSL_free(contextPointer->sslInstance);
                        if (nullptr != contextPointer->sslContext)
                            SSL_CTX_free(contextPointer->sslContext);

                        if (m_eventCallbacks.contains(contextPointer->id))
                        {
                            for (const auto &[eventType, eventCallback] : m_eventCallbacks[contextPointer->id])
                                eventCallback(false, *contextPointer);
                        }

                        auto endpoint = contextPointer->transport->peer_endpoint();
                        LogInfo("The adbd server %s:%d has been disconnected", endpoint.ip().data(), endpoint.port());

                        // Remove network context
                        {
                            std::unique_lock<std::mutex> locker(m_networkContextsMutex);

                            m_networkContexts.erase(*contextPointer);
                        }
                    }

                    removeList.clear();
                }
                if (m_networkContexts.empty())
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    continue;
                }

                // Register fds
                fd_set readFds{};
                for (const auto &context : m_networkContexts)
                    FD_SET(context.transport->native_handle(), &readFds);

                // Wait event
                timeval timeout{.tv_sec = 1};
                auto status = ::select(FD_SETSIZE, &readFds, nullptr, nullptr, &timeout);
                if (0 == status)
                    continue;
                else if (0 > status)
                {
                    auto errorCode = yasio::xxsocket::get_last_errno();
                    if (10038 != errorCode)
                    {
                        LogError("Function select error result:%d errorCode:%d errorString:%s", status, errorCode, yasio::xxsocket::strerror(errorCode));
                        break;
                    }
                }

                // Process event
                for (const auto &context : m_networkContexts)
                {
                    if (!FD_ISSET(context.transport->native_handle(), &readFds))
                        continue;

                    if (sizeof(ADBMessage::Header) != ReadData(context, m_readPacketStream.Data(), sizeof(ADBMessage::Header)))
                    {
                        auto errorCode = yasio::xxsocket::get_last_errno();
                        if (0 == errorCode || 10038 == errorCode || 10054 == errorCode)
                            removeList.push_back(&context);

                        LogFailed("ReadData(%zd) failed errorCode:%d errorString:%s", sizeof(ADBMessage::Header), errorCode, yasio::xxsocket::strerror(errorCode));
                        continue;
                    }

                    m_readPacketStream.Resize(sizeof(ADBMessage::Header));
                    m_readPacketStream.Seek(offsetof(ADBMessage::Header, dataLength));
                    auto dataLength = m_readPacketStream.Read<uint32_t>();
                    if (0 < dataLength)
                    {
                        if (dataLength != ReadData(context, m_readPacketStream.Data() + sizeof(ADBMessage::Header), dataLength))
                        {
                            auto errorCode = yasio::xxsocket::get_last_errno();
                            if (0 == errorCode || 10038 == errorCode || 10054 == errorCode)
                                removeList.push_back(&context);

                            LogFailed("ReadData(%d) failed errorCode:%d errorString:%s", dataLength, errorCode, yasio::xxsocket::strerror(errorCode));
                            continue;
                        }
                    }

                    m_readPacketStream.Resize(sizeof(ADBMessage::Header) + dataLength);
                    m_readPacketStream.Seek(0);
                    m_readPacketStream >> m_readMessageData;
                    OnADBMessage(context);
                }
            }
        });
}

ADBService::~ADBService()
{
    m_work = false;
    if (nullptr != m_networkThread)
        if (m_networkThread->joinable())
            m_networkThread->join();
}

uint32_t ADBService::RandomNumber() const
{
    static std::random_device seeder;
    static std::ranlux48 engine(seeder());
    static std::uniform_int_distribution<uint32_t> distribution(1, std::numeric_limits<uint32_t>::max());

    return distribution(engine);
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

int ADBService::ReadData(const NetworkContext &context, void *buffer, size_t bufferLength)
{
    if (nullptr == context.sslInstance)
        return context.transport->recv_n(buffer, static_cast<int>(bufferLength), static_cast<std::chrono::microseconds>(std::chrono::seconds(1)));

    int readed = 0;
    while (readed < bufferLength)
    {
        auto result = SSL_read(context.sslInstance, reinterpret_cast<char *>(buffer) + readed, static_cast<int>(bufferLength) - readed);

        if (0 == result)
            return result;
        else if (-1 == result)
        {
            auto status = SSL_get_error(context.sslInstance, result);

            if (SSL_ERROR_WANT_READ == status)
            {
                if (0 > yasio::xxsocket::handle_read_ready(context.transport->native_handle(), static_cast<std::chrono::microseconds>(std::chrono::seconds(1))))
                    return -1;

                continue;
            }
            else if (SSL_ERROR_SSL == status)
                return -1;

            char errorMessage[1024]{};
            LogError("SSL unknow read error: %d %s", status, ERR_error_string_n(status, errorMessage, sizeof(errorMessage)));
        }

        readed += result;
    }

    return bufferLength == readed ? readed : -1;
}

int ADBService::SendData(const NetworkContext &context, void *data, size_t dataLength)
{
    if (nullptr == context.sslInstance)
        return context.transport->send(data, static_cast<int>(dataLength));

    return SSL_write(context.sslInstance, data, static_cast<int>(dataLength));
}

bool ADBService::DoTlsHandshake(NetworkContext &context)
{
    context.sslContext = SSL_CTX_new(SSLv23_client_method());
    if (nullptr == context.sslContext)
    {
        LogFailed("DoTlsHandshake: SSL_CTX_new failed");

        return false;
    }

    context.sslInstance = SSL_new(context.sslContext);
    if (nullptr == context.sslInstance)
    {
        LogFailed("DoTlsHandshake: SSL_new failed");

        SSL_CTX_free(context.sslContext);
        context.sslContext = nullptr;

        return false;
    }

    if (!context.privateKey.empty())
    {
        char errorMessage[1024]{};
        auto evpPrivateKey = EvpPkeyFromPEM(context.privateKey);
        auto x509Certificate = GenerateX509Certificate(evpPrivateKey.get());

        if (1 != SSL_use_PrivateKey(context.sslInstance, evpPrivateKey.get()) || 1 != SSL_use_certificate(context.sslInstance, x509Certificate.get()))
        {
            LogFailed("SSL_use_PrivateKey or SSL_use_certificate failed");

            SSL_free(context.sslInstance);
            context.sslInstance = nullptr;
            SSL_CTX_free(context.sslContext);
            context.sslContext = nullptr;

            return false;
        }
    }
    else
        LogInfo("SSL certificate and private key are not set, which may cause handshake failure");

    SSL_set_fd(context.sslInstance, static_cast<int>(context.transport->native_handle()));
    SSL_set_connect_state(context.sslInstance);
    SSL_do_handshake(context.sslInstance);

    return true;
}

void ADBService::OnADBMessage(const NetworkContext &context)
{
    switch (m_readMessageData.header.command)
    {
    case ADBCommand::WRTE:
    {
        // Response READY message
        static PacketStream readyMessageBuffer;
        static ADBMessageData readyMessage;

        readyMessage.FillMessage(ADBCommand::OKAY, "");
        readyMessage.header.param1 = m_readMessageData.header.param2;
        readyMessage.header.param2 = m_readMessageData.header.param1;
        readyMessageBuffer.Clear();
        readyMessageBuffer << readyMessage;

        SendData(context, readyMessageBuffer.Data(), readyMessageBuffer.Size());

        if (!m_eventCallbacks.contains(context.id) || !m_eventCallbacks[context.id].contains(m_readMessageData.header.command))
            return; // Ignore response message

        if (context.syncMode)
            break; // Hand over to follow-up processing

        static char writeDoneFlags[] = {0x03, 0x01, 0x00, 0x00, 0x00, 0x00};

        auto &modifyContext = const_cast<NetworkContext &>(context);
        if (modifyContext.isWritePacketCompletion)
        {
            modifyContext.writePacketCompletionBuffer.clear();
            modifyContext.isWritePacketCompletion = false;
        }

        modifyContext.writePacketCompletionBuffer.insert(
            modifyContext.writePacketCompletionBuffer.end(),
            m_readMessageData.data,
            m_readMessageData.data + m_readMessageData.header.dataLength);

        if (
            sizeof(writeDoneFlags) == m_readMessageData.header.dataLength && 0 == memcmp(writeDoneFlags, m_readMessageData.data, sizeof(writeDoneFlags)) ||
            sizeof(writeDoneFlags) < m_readMessageData.header.dataLength && 0 == memcmp(writeDoneFlags, m_readMessageData.data + (m_readMessageData.header.dataLength - sizeof(writeDoneFlags)), sizeof(writeDoneFlags)))
        {
            modifyContext.isWritePacketCompletion = true;
            m_readMessageData.data = modifyContext.writePacketCompletionBuffer.data();
            m_readMessageData.header.dataLength = static_cast<uint32_t>(
                modifyContext.writePacketCompletionBuffer.size() >= sizeof(writeDoneFlags) ? modifyContext.writePacketCompletionBuffer.size() - sizeof(writeDoneFlags) : modifyContext.writePacketCompletionBuffer.size());

            break; // Hand over to follow-up processing
        }

        return; // Wait for command WRITE done
    }
    case ADBCommand::CLSE:
    {
        auto paramsArray = reinterpret_cast<uint32_t *>(m_readPacketStream.Data() + offsetof(ADBMessage::Header, param1));

        auto exchangeParameter = paramsArray[0];
        paramsArray[0] = paramsArray[1];
        paramsArray[1] = exchangeParameter;

        SendData(context, m_readPacketStream.Data(), m_readPacketStream.Size());
        return;
    }
    case ADBCommand::STLS:
    {
        LogInfo("Handshake failed, need perform TLS handshake");

        if (m_readPacketStream.Size() != SendData(context, m_readPacketStream.Data(), m_readPacketStream.Size()))
        {
            LogFailed("Request TLS handshake failed");

            return;
        }
        if (!DoTlsHandshake(const_cast<NetworkContext &>(context)))
            LogFailed("DoTlsHandshake failed");
        return;
    }
    default:
        break;
    }

    if (m_eventCallbacks.contains(context.id) && m_eventCallbacks[context.id].contains(m_readMessageData.header.command))
    {
        m_eventCallbacks[context.id][m_readMessageData.header.command](true, context);
        m_eventCallbacks[context.id].erase(m_readMessageData.header.command);
    }
}

std::optional<ADBService::PairingResult> ADBService::Pairing(const std::string_view &password, const std::string_view &ip, uint16_t port, const std::string_view &privateKeyString)
{
    auto transport = std::make_unique<yasio::xxsocket>();
    if (!transport->open())
        return std::nullopt;

    // Connect to device
    if (0 > transport->connect(ip.data(), port))
    {
        auto errorCode = yasio::xxsocket::get_last_errno();

        LogFailed("Connect to %s:%d failed errorCode:%d errorString:%s", ip.data(), port, errorCode, yasio::xxsocket::strerror(errorCode));
        return std::nullopt;
    }

    // Make network context
    NetworkContext context{std::move(transport), privateKeyString};
    if (context.privateKey.empty())
    {
        auto evpPrivateKey = CreateRSA2048PrivateKey();
        if (nullptr == evpPrivateKey)
        {
            LogFailed("CreateRSA2048PrivateKey for %s:%d failed", ip.data(), port);
            return std::nullopt;
        }
        context.privateKey = EVPKeyToPEMString(evpPrivateKey.get());
    }

    // Calculate public key
    std::string publicKey;
    auto evpPrivateKey = EvpPkeyFromPEM(context.privateKey);
    auto rsaPrivateKey = EVP_PKEY_get0_RSA(evpPrivateKey.get());
    if (nullptr == rsaPrivateKey)
    {
        LogFailed("Get ras private key for %s:%d failed", ip.data(), port);
        return std::nullopt;
    }
    if (!CalculatePublicKey(&publicKey, rsaPrivateKey))
    {
        LogFailed("CalculatePublicKey for %s:%d failed", ip.data(), port);
        return std::nullopt;
    }

    // Do tls handshake
    if (!DoTlsHandshake(context))
    {
        LogFailed("DoTlsHandshake for %s:%d failed", ip.data(), port);
        return std::nullopt;
    }

    // Make password sequence
    std::vector<char> passwordSequence(password.begin(), password.end());
    passwordSequence.insert(passwordSequence.end(), 64, 0);
    if (0 == SSL_export_keying_material(context.sslInstance, reinterpret_cast<uint8_t *>(passwordSequence.data() + password.size()), 64, "adb-label", 10, nullptr, 0, false))
    {
        LogFailed("SSL_export_keying_material for %s:%d failed", ip.data(), port);
        return std::nullopt;
    }

    // New SPAKE2 context
    static const uint8_t kClientName[] = "adb pair client";
    static const uint8_t kServerName[] = "adb pair server";
    std::unique_ptr<SPAKE2_CTX, decltype(&SPAKE2_CTX_free)> spake2Context(SPAKE2_CTX_new(spake2_role_alice, kClientName, sizeof(kClientName), kServerName, sizeof(kServerName)), SPAKE2_CTX_free);
    if (nullptr == spake2Context)
    {
        LogFailed("Pairing: unable to create a SPAKE2 context for %s:%d", ip.data(), port);
        return std::nullopt;
    }

    // Generate password data
    size_t dataLength = 0;
    uint8_t messageBuffer[SPAKE2_MAX_MSG_SIZE]{}, keyBuffer[SPAKE2_MAX_KEY_SIZE]{};
    int status = SPAKE2_generate_msg(spake2Context.get(), messageBuffer, &dataLength, SPAKE2_MAX_MSG_SIZE, reinterpret_cast<uint8_t *>(passwordSequence.data()), passwordSequence.size());
    if (1 != status || 0 == dataLength)
    {
        LogFailed("Pairing: unable to generate password data");
        return std::nullopt;
    }

    // Send password data
    PacketStream pairingPacketStream;
    PairingPacketData pairingData;

    pairingData.FillPacket(PairingPacketData::Type::SPAKE2_MSG, messageBuffer, static_cast<uint32_t>(dataLength));
    pairingPacketStream << pairingData;
    if (pairingPacketStream.Size() != SendData(context, pairingPacketStream.Data(), pairingPacketStream.Size()))
    {
        LogFailed("Pairing: unable to send password data");
        return std::nullopt;
    }

    // Read key data
    PairingPacketHeaderData pairingHeaderData;
    pairingPacketStream.Clear();
    pairingPacketStream.Resize(PairingPacketHeaderData::HEADER_SIZE);
    if (PairingPacketHeaderData::HEADER_SIZE != ReadData(context, pairingPacketStream.Data(), PairingPacketHeaderData::HEADER_SIZE))
    {
        LogFailed("Pairing: unable to read key data header");
        return std::nullopt;
    }
    pairingPacketStream >> pairingHeaderData;
    if (SPAKE2_MAX_MSG_SIZE != pairingHeaderData.dataLength || PairingPacketData::Type::SPAKE2_MSG != pairingHeaderData.type)
    {
        LogFailed("Pairing: invalid key data header");
        return std::nullopt;
    }
    if (SPAKE2_MAX_MSG_SIZE != ReadData(context, messageBuffer, SPAKE2_MAX_MSG_SIZE))
    {
        LogFailed("Pairing: unable to read key data");
        return std::nullopt;
    }
    // Process key data
    SPAKE2_process_msg(spake2Context.get(), keyBuffer, &dataLength, SPAKE2_MAX_KEY_SIZE, messageBuffer, SPAKE2_MAX_MSG_SIZE);
    if (1 != status || 0 == dataLength)
    {
        LogFailed("Pairing: unable to process key data");
        return std::nullopt;
    }

    // Send public key
    Aes128Gcm aesGcm(keyBuffer, dataLength);
    PairingPacketPeerInfoData peerInfo;

    peerInfo.FillData(PairingPacketPeerInfoData::Type::ADB_RSA_PUB_KEY, publicKey.data(), static_cast<uint32_t>(publicKey.size()));
    pairingPacketStream.Clear();
    pairingPacketStream << peerInfo;

    std::vector<uint8_t> encryptDataBuffer(aesGcm.EncryptedSize(pairingPacketStream.Size()));
    auto encryptDataSize = aesGcm.Encrypt(reinterpret_cast<uint8_t *>(pairingPacketStream.Data()), pairingPacketStream.Size(), encryptDataBuffer.data(), encryptDataBuffer.size());
    if (!encryptDataSize.has_value())
    {
        LogFailed("Pairing: unable to encrypt pairing data");
        return std::nullopt;
    }

    pairingData.FillPacket(PairingPacketData::Type::PEER_INFO, encryptDataBuffer.data(), static_cast<uint32_t>(*encryptDataSize));
    pairingPacketStream.Clear();
    pairingPacketStream << pairingData;
    if (pairingPacketStream.Size() != SendData(context, pairingPacketStream.Data(), pairingPacketStream.Size()))
    {
        LogFailed("Pairing: unable to send public key data");
        return std::nullopt;
    }

    // Read peer info
    pairingPacketStream.Clear();
    pairingPacketStream.Resize(PairingPacketHeaderData::HEADER_SIZE);
    if (PairingPacketHeaderData::HEADER_SIZE != ReadData(context, pairingPacketStream.Data(), PairingPacketHeaderData::HEADER_SIZE))
    {
        LogFailed("Pairing: unable to read peer info header");
        return std::nullopt;
    }
    pairingPacketStream >> pairingHeaderData;
    if (PairingPacketData::Type::PEER_INFO != pairingHeaderData.type)
    {
        LogFailed("Pairing: invalid packet");
        return std::nullopt;
    }
    pairingPacketStream.Clear();
    pairingPacketStream.Resize(pairingHeaderData.dataLength);
    if (pairingHeaderData.dataLength != ReadData(context, pairingPacketStream.Data(), pairingHeaderData.dataLength))
    {
        LogFailed("Pairing: unable to read peer info data");
        return std::nullopt;
    }

    // Decrypt data
    std::vector<uint8_t> decryptDataBuffer(aesGcm.DecryptedSize(pairingHeaderData.dataLength));
    auto decryptDataSize = aesGcm.Decrypt(reinterpret_cast<uint8_t *>(pairingPacketStream.Data()), pairingHeaderData.dataLength, decryptDataBuffer.data(), decryptDataBuffer.size());
    if (!decryptDataSize.has_value())
    {
        LogFailed("Pairing: unable to decrypt pairing data");
        return std::nullopt;
    }
    if (MAX_PEER_INFO_SIZE != *decryptDataSize || static_cast<uint8_t>(PairingPacketPeerInfoData::Type::ADB_DEVICE_GUID) != decryptDataBuffer[0])
    {
        LogFailed("Pairing: invalid peer info data");
        return std::nullopt;
    }

    std::string peerGUID(reinterpret_cast<char *>(decryptDataBuffer.data() + 1));
    LogSucceeded("Successfully paired to %s:%d [guid=%s]", ip.data(), port, peerGUID.data());

    return ADBService::PairingResult{context.privateKey, publicKey};
}

int ADBService::Connect(const std::string_view &ip, uint16_t port, const std::string_view &privateKeyString)
{
    int deviceId = -1;
    auto transport = std::make_unique<yasio::xxsocket>();

    if (!transport->open())
        return deviceId;

    if (0 > transport->connect_n(ip.data(), port, static_cast<std::chrono::microseconds>(std::chrono::seconds(1))))
    {
        auto errorCode = yasio::xxsocket::get_last_errno();

        LogFailed("Connect to %s:%d failed errorCode:%d errorString:%s", ip.data(), port, errorCode, yasio::xxsocket::strerror(errorCode));

        return deviceId;
    }

    // Make network context
    auto contextIt = m_networkContexts.end();
    {
        std::unique_lock<std::mutex> locker(m_networkContextsMutex);

        auto it = m_networkContexts.emplace(std::move(transport), privateKeyString);
        contextIt = it.first;
    }
    if (contextIt == m_networkContexts.end())
    {
        LogError("Unknow error: contextIt == m_networkContexts.end()");

        return deviceId;
    }

    // Register event
    std::promise<int> result;
    m_eventCallbacks[contextIt->id].emplace(
        ADBCommand::CNXN,
        [&](bool state, const NetworkContext &context)
        {
            if (!state)
            {
                result.set_value(deviceId);
                return;
            }

            m_deviceInfos.emplace(
                context.id,
                DeviceInfo{
                    .id = context.id,
                    .infoString = {m_readMessageData.data, m_readMessageData.header.dataLength},
                    .networkContext = &context,
                });
            auto &device = m_deviceInfos[context.id];

            auto deviceInfo = StringSplitAsciiView(device.infoString, "::");
            if (deviceInfo.size() < 2 || "device" != deviceInfo[0])
            {
                result.set_value(deviceId);
                return;
            }

            deviceInfo = StringSplitAsciiView(deviceInfo[1], ";");
            if (deviceInfo.size() < 3)
            {
                result.set_value(deviceId);
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

            result.set_value(static_cast<int>(context.id));
        });

    // Send connect message
    m_writeMessageData.FillMessage(ADBCommand::CNXN, "host::features=shell_v2,cmd,stat_v2,ls_v2,fixed_push_mkdir,apex,abb,fixed_push_symlink_timestamp,abb_exec,remount_shell,track_app,sendrecv_v2,sendrecv_v2_brotli,sendrecv_v2_lz4,sendrecv_v2_zstd,sendrecv_v2_dry_run_send,openscreen_mdns");
    m_writeMessageData.header.param1 = 0x1000001;
    m_writeMessageData.header.param2 = 0x100000;
    m_writePacketStream.Clear();
    m_writePacketStream << m_writeMessageData;
    if (m_writePacketStream.Size() != SendData(*contextIt, m_writePacketStream.Data(), m_writePacketStream.Size()))
    {
        auto errorCode = yasio::xxsocket::get_last_errno();

        LogFailed("Send connect request to %s:%d failed errorCode:%d errorString:%s", ip.data(), port, errorCode, yasio::xxsocket::strerror(errorCode));

        return deviceId;
    }

    return result.get_future().get();
}

void ADBService::DisConnect(int deviceId)
{
    if (m_deviceInfos.contains(deviceId))
    {
        auto &context = *m_deviceInfos[deviceId].networkContext;

        context.transport->close();
        if (nullptr != context.sslInstance)
            SSL_free(context.sslInstance);
        if (nullptr != context.sslContext)
            SSL_CTX_free(context.sslContext);

        m_deviceInfos.erase(deviceId);
    }
}

bool ADBService::Shell(int deviceId, const std::string_view &command)
{
    if (!m_deviceInfos.contains(deviceId))
    {
        LogFailed("ADB shell no that device: %d", deviceId);

        return false;
    }

    uint32_t localId = RandomNumber();
    std::string shellCommand = "shell,v2,TERM=xterm-256color,raw:";
    shellCommand.append(command);

    std::promise<bool> waitReadyMessage;
    m_eventCallbacks[deviceId].emplace(
        ADBCommand::OKAY,
        [&](bool state, const NetworkContext &context)
        {
            waitReadyMessage.set_value(state && localId == m_readMessageData.header.param2);
        });

    m_writeMessageData.FillMessage(ADBCommand::OPEN, "");
    m_writeMessageData.header.param1 = localId;
    m_writeMessageData.header.param2 = 0x0;
    m_writeMessageData.header.dataLength = static_cast<uint32_t>(shellCommand.length());
    m_writeMessageData.data = const_cast<char *>(shellCommand.data());
    m_writePacketStream.Clear();
    m_writePacketStream << m_writeMessageData;

    SendData(*m_deviceInfos[deviceId].networkContext, m_writePacketStream.Data(), m_writePacketStream.Size());

    return waitReadyMessage.get_future().get();
}

void ADBService::Push(int deviceId, void *data, size_t dataLength, const std::filesystem::path &writeToPath)
{
    if (!m_deviceInfos.contains(deviceId))
    {
        LogFailed("ADB push no that device: %d", deviceId);

        return;
    }
    if (nullptr == data || 0 == dataLength)
        return;

    // Open sync mode
    uint32_t localId = RandomNumber();
    uint32_t remoteId = 0;

    std::promise<bool> waitReadyMessage{};
    auto WaitReadyMethod = [&](bool state, const NetworkContext &context)
    {
        if (0 == remoteId)
        {
            remoteId = m_readMessageData.header.param1;
            waitReadyMessage.set_value(state && localId == m_readMessageData.header.param2);

            return;
        }

        waitReadyMessage.set_value(state);
    };

    m_writeMessageData.FillMessage(ADBCommand::OPEN, "sync:");
    m_writeMessageData.header.param1 = localId;
    m_writeMessageData.header.param2 = 0x0;
    m_writePacketStream.Clear();
    m_writePacketStream << m_writeMessageData;

    m_eventCallbacks[deviceId].emplace(ADBCommand::OKAY, WaitReadyMethod);
    SendData(*m_deviceInfos[deviceId].networkContext, m_writePacketStream.Data(), m_writePacketStream.Size());
    if (!waitReadyMessage.get_future().get())
    {
        LogFailed("ADB push open sync mode failed: %d", deviceId);

        return;
    }

    // TODO: The following code looks like it is not necessary, maybe it will be removed in the future.
    // // Try to stat a file
    // waitReadyMessage = {};

    // m_writeMessageData.FillMessage(ADBCommand::WRTE, "");
    // m_writeMessageData.header.param1 = localId;
    // m_writeMessageData.header.param2 = remoteId;
    // m_writePacketStream.Clear();
    // m_writePacketStream << m_writeMessageData;
    // m_writePacketStream.Write(ID_STAT_V2);
    // m_writePacketStream.Write(writeToPath.string());
    // *reinterpret_cast<uint32_t *>(m_writePacketStream.Data() + offsetof(ADBMessage::Header, dataLength)) = 8 + static_cast<uint32_t>(writeToPath.string().size());

    // m_eventCallbacks[deviceId].emplace(ADBCommand::OKAY, WaitReadyMethod);
    // SendData(*m_deviceInfos[deviceId].networkContext, m_writePacketStream.Data(), m_writePacketStream.Size());
    // if (!waitReadyMessage.get_future().get())
    // {
    //     LogFailed("ADB push stat a file failed: %d", deviceId);

    //     return;
    // }

    // Send file data
    waitReadyMessage = {};

    m_writeMessageData.FillMessage(ADBCommand::WRTE, "");
    m_writeMessageData.header.param1 = localId;
    m_writeMessageData.header.param2 = remoteId;
    m_writePacketStream.Clear();
    m_writePacketStream << m_writeMessageData;
    m_writePacketStream.Write(ID_SEND_V2); // Only use v2
    m_writePacketStream.Write(writeToPath.string());
    m_writePacketStream.Write(ID_SEND_V2);
    m_writePacketStream.Write<uint32_t>(0x81B6); // File mode(permission): 0x81B6 -> rw-rw-rw-(666)
    m_writePacketStream.Write(SyncFlag::None);
    *reinterpret_cast<uint32_t *>(m_writePacketStream.Data() + offsetof(ADBMessage::Header, dataLength)) = static_cast<uint32_t>(m_writePacketStream.Size() - sizeof(ADBMessage::Header));

    m_eventCallbacks[deviceId].emplace(ADBCommand::OKAY, WaitReadyMethod);
    SendData(*m_deviceInfos[deviceId].networkContext, m_writePacketStream.Data(), m_writePacketStream.Size());
    if (!waitReadyMessage.get_future().get())
    {
        LogFailed("ADB push send file info failed: %d", deviceId);

        return;
    }

    auto block = dataLength / SYNC_DATA_MAX;
    auto remaining = dataLength % SYNC_DATA_MAX;
    auto SendChunkData = [&](void *buffer, size_t size)
    {
        waitReadyMessage = {};

        m_writePacketStream.Clear();
        m_writePacketStream << m_writeMessageData;
        m_writePacketStream.Write(ID_DATA);
        m_writePacketStream.Write(static_cast<uint32_t>(size));
        m_writePacketStream.WriteBytes(buffer, size);
        *reinterpret_cast<uint32_t *>(m_writePacketStream.Data() + offsetof(ADBMessage::Header, dataLength)) = static_cast<uint32_t>(m_writePacketStream.Size() - sizeof(ADBMessage::Header));

        m_eventCallbacks[deviceId].emplace(ADBCommand::OKAY, WaitReadyMethod);
        SendData(*m_deviceInfos[deviceId].networkContext, m_writePacketStream.Data(), m_writePacketStream.Size());
        if (!waitReadyMessage.get_future().get())
        {
            LogFailed("ADB push send file data failed: %d", deviceId);

            return false;
        }

        return true;
    };

    for (size_t i = 0; i < block; ++i)
    {
        if (!SendChunkData(reinterpret_cast<char *>(data) + i * SYNC_DATA_MAX, SYNC_DATA_MAX))
            return;
    }
    if (0 != remaining)
    {
        if (!SendChunkData(reinterpret_cast<char *>(data) + block * SYNC_DATA_MAX, remaining))
            return;
    }

    waitReadyMessage = {};
    m_writePacketStream.Clear();
    m_writePacketStream << m_writeMessageData;
    m_writePacketStream.Write(ID_DONE);
    m_writePacketStream.Write(static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count())); // File last modify timestamp
    *reinterpret_cast<uint32_t *>(m_writePacketStream.Data() + offsetof(ADBMessage::Header, dataLength)) = static_cast<uint32_t>(m_writePacketStream.Size() - sizeof(ADBMessage::Header));

    m_eventCallbacks[deviceId].emplace(ADBCommand::OKAY, WaitReadyMethod);
    SendData(*m_deviceInfos[deviceId].networkContext, m_writePacketStream.Data(), m_writePacketStream.Size());
    if (!waitReadyMessage.get_future().get())
    {
        LogFailed("ADB push send file last modify timestamp failed: %d", deviceId);

        return;
    }

    // Quit sync mode
    waitReadyMessage = {};

    m_writeMessageData.FillMessage(ADBCommand::WRTE, "QUIT\x00\x00\x00\x00");
    m_writeMessageData.header.param1 = localId;
    m_writeMessageData.header.param2 = remoteId;
    m_writePacketStream.Clear();
    m_writePacketStream << m_writeMessageData;

    m_eventCallbacks[deviceId].emplace(ADBCommand::OKAY, WaitReadyMethod);
    SendData(*m_deviceInfos[deviceId].networkContext, m_writePacketStream.Data(), m_writePacketStream.Size());
    if (!waitReadyMessage.get_future().get())
    {
        LogError("ADB push quit sync mode failed: %d", deviceId);

        return;
    }
}
