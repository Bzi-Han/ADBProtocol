#ifndef ADB_PROTOCOL_H // !ADB_PROTOCOL_H
#define ADB_PROTOCOL_H

#include <stdint.h>

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

#endif // !ADB_PROTOCOL_H
