#include "ADBProtoImpl.h"

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