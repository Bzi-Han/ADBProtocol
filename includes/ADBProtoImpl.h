#ifndef ADB_PROTO_IMPL_H // !ADB_PROTO_IMPL_H
#define ADB_PROTO_IMPL_H

#include "PacketStream.h"
#include "ADBProtocol.h"

#include <yasio/yasio/yasio.hpp>

template <>
struct PacketStreamTrait<yasio::inet::packet_t> : PacketStreamTraitTools
{
    inline static size_t Write(PacketStream *self, const yasio::inet::packet_t &data)
    {
        return WriteBytes(self, const_cast<char *>(data.data()), data.size());
    }
};

struct ADBMessageData : ADBMessage, PacketSerializable
{
    virtual void DeSerialize(PacketStream *self) override;

    virtual void Serialize(PacketStream *self) const override;
};

#endif // !ADB_PROTO_IMPL_H