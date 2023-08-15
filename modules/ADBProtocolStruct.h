#ifndef ADB_PROTOCOL_STRUCT_H // !ADB_PROTOCOL_STRUCT_H
#define ADB_PROTOCOL_STRUCT_H

#include <stdint.h>

#define MKID(a, b, c, d) uint32_t((a) | ((b) << 8) | ((c) << 16) | ((d) << 24))

#define ID_LSTAT_V1 MKID('S', 'T', 'A', 'T')
#define ID_STAT_V2 MKID('S', 'T', 'A', '2')
#define ID_LSTAT_V2 MKID('L', 'S', 'T', '2')

#define ID_LIST_V1 MKID('L', 'I', 'S', 'T')
#define ID_LIST_V2 MKID('L', 'I', 'S', '2')
#define ID_DENT_V1 MKID('D', 'E', 'N', 'T')
#define ID_DENT_V2 MKID('D', 'N', 'T', '2')

#define ID_SEND_V1 MKID('S', 'E', 'N', 'D')
#define ID_SEND_V2 MKID('S', 'N', 'D', '2')
#define ID_RECV_V1 MKID('R', 'E', 'C', 'V')
#define ID_RECV_V2 MKID('R', 'C', 'V', '2')
#define ID_DONE MKID('D', 'O', 'N', 'E')
#define ID_DATA MKID('D', 'A', 'T', 'A')
#define ID_OKAY MKID('O', 'K', 'A', 'Y')
#define ID_FAIL MKID('F', 'A', 'I', 'L')
#define ID_QUIT MKID('Q', 'U', 'I', 'T')
#define SYNC_DATA_MAX uint32_t(64 * 1024)

#define MAX_PEER_INFO_SIZE uint32_t(8192)

enum class SyncFlag : uint32_t
{
    None = 0,
    Brotli = 1,
    LZ4 = 2,
    Zstd = 4,
    DryRun = 0x8000'0000U,
};

enum class ADBCommand : uint32_t
{
    SYNC = 0x434e5953,
    CNXN = 0x4E584E43,
    OPEN = 0x4E45504F,
    OKAY = 0x59414B4F,
    CLSE = 0x45534C43,
    WRTE = 0x45545257,
    AUTH = 0x48545541,
    STLS = 0x534C5453,
};

struct ADBMessage
{
    struct Header
    {
        ADBCommand command;
        uint32_t param1 = 0;
        uint32_t param2 = 0;
        uint32_t dataLength;
        uint32_t dataCRC32 = 0;
        uint32_t magic; // command ^ 0xFFFFFFFF
    } header;

    char *data;

    template <uint32_t dimension>
    ADBMessage &FillMessage(ADBCommand command, const char (&message)[dimension])
    {
        header.command = command;
        header.magic = static_cast<uint32_t>(command) ^ 0xFFFFFFFF;
        header.dataLength = dimension - 1;
        data = const_cast<char *>(message);

        return *this;
    }
};

struct PairingPacket
{
    enum class Type : uint8_t
    {
        SPAKE2_MSG = 0,
        PEER_INFO = 1,
    };

    struct Header
    {
        uint8_t version;     // PairingPacket version
        Type type;           // the type of packet (PairingPacket.Type)
        uint32_t dataLength; // Size of the payload in bytes
    } header;

    char *data;

    PairingPacket &FillPacket(Type type, void *data, uint32_t dataLength)
    {
        header.version = 0x01;
        header.type = type;
        header.dataLength = dataLength;
        this->data = reinterpret_cast<char *>(data);

        return *this;
    }
};

struct PairingPacketPeerInfo
{
    enum Type : uint8_t
    {
        ADB_RSA_PUB_KEY = 0,
        ADB_DEVICE_GUID = 1,
    };

    Type type;
    uint8_t data[MAX_PEER_INFO_SIZE - 1];

    PairingPacketPeerInfo &FillData(Type type, void *data, uint32_t dataLength)
    {
        this->type = type;
        memset(this->data, 0, sizeof(this->data));
        memcpy(this->data, data, dataLength);

        return *this;
    }
};

#endif // !ADB_PROTOCOL_STRUCT_H
