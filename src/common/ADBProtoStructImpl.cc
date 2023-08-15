#include "ADBProtoStructImpl.h"

void ADBMessageData::DeSerialize(PacketStream *self)
{
    self->Read(header.command);
    self->Read(header.param1);
    self->Read(header.param2);
    self->Read(header.dataLength);
    self->Read(header.dataCRC32);
    self->Read(header.magic);
    data = self->ReadBytesRef(header.dataLength);
}

void ADBMessageData::Serialize(PacketStream *self) const
{
    self->Write(header.command);
    self->Write(header.param1);
    self->Write(header.param2);
    self->Write(header.dataLength);
    self->Write(header.dataCRC32);
    self->Write(header.magic);
    self->WriteBytes(data, header.dataLength);
}

void PairingPacketData::DeSerialize(PacketStream *self)
{
    self->Read(header.version);
    self->Read(header.type);
    self->Read(header.dataLength);
    header.dataLength = BYTE_SWAP_32(header.dataLength);
    data = self->ReadBytesRef(header.dataLength);
}

void PairingPacketData::Serialize(PacketStream *self) const
{
    self->Write(header.version);
    self->Write(header.type);
    self->Write(BYTE_SWAP_32(header.dataLength));
    self->WriteBytes(data, header.dataLength);
}

void PairingPacketHeaderData::DeSerialize(PacketStream *self)
{
    self->Read(version);
    self->Read(type);
    self->Read(dataLength);
    dataLength = BYTE_SWAP_32(dataLength);
}

void PairingPacketHeaderData::Serialize(PacketStream *self) const
{
    self->Write(version);
    self->Write(type);
    self->Write(BYTE_SWAP_32(dataLength));
}

void PairingPacketPeerInfoData::DeSerialize(PacketStream *self)
{
    self->Read(type);
    self->ReadBytes(data, sizeof(data));
}

void PairingPacketPeerInfoData::Serialize(PacketStream *self) const
{
    self->Write(type);
    self->WriteBytes(const_cast<uint8_t *>(data), sizeof(data));
}