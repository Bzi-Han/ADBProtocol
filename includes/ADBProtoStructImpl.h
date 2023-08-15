#ifndef ADB_PROTO_IMPL_H // !ADB_PROTO_IMPL_H
#define ADB_PROTO_IMPL_H

#include "PacketStream.h"
#include "ADBProtocolStruct.h"

struct ADBMessageData : ADBMessage, PacketSerializable
{
    virtual void DeSerialize(PacketStream *self) override;

    virtual void Serialize(PacketStream *self) const override;
};

struct PairingPacketData : PairingPacket, PacketSerializable
{
    virtual void DeSerialize(PacketStream *self) override;

    virtual void Serialize(PacketStream *self) const override;
};

struct PairingPacketHeaderData : PairingPacket::Header, PacketSerializable
{
    constexpr static size_t HEADER_SIZE = 6;

    virtual void DeSerialize(PacketStream *self) override;

    virtual void Serialize(PacketStream *self) const override;
};

struct PairingPacketPeerInfoData : PairingPacketPeerInfo, PacketSerializable
{
    constexpr static size_t DATA_SIZE = 8192;

    virtual void DeSerialize(PacketStream *self) override;

    virtual void Serialize(PacketStream *self) const override;
};

#endif // !ADB_PROTO_IMPL_H