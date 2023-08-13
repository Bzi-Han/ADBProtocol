#include "PacketStream.h"

void PacketStream::Reserve(size_t size)
{
    m_buffer.reserve(size);
}

void PacketStream::Clear()
{
    m_index = 0;
    m_buffer.clear();
}

std::vector<char> &PacketStream::Buffer() { return m_buffer; }

ptrdiff_t PacketStream::Tell() const { return m_index; }

bool PacketStream::Seek(ptrdiff_t offset, int origin)
{
    switch (origin)
    {
    case SEEK_SET:
        if (m_buffer.size() < static_cast<size_t>(offset))
            return false;

        m_index = offset;
        break;
    case SEEK_CUR:
        if (m_buffer.size() < static_cast<size_t>(m_index + offset))
            return false;

        m_index += offset;
        break;
    case SEEK_END:
        if (0 < offset || 0 > m_buffer.size() + offset)
            return false;

        m_index = m_buffer.size() + offset;
        break;
    }

    return true;
}

void PacketStream::ReadBytes(void *buffer, size_t size)
{
    PacketStreamTraitTools::ReadBytes(this, reinterpret_cast<char *>(buffer), size);
}
char *PacketStream::ReadBytesRef(size_t size)
{
    return PacketStreamTraitTools::ReadBytesRef(this, size);
}

void PacketStream::WriteBytes(void *buffer, size_t size)
{
    PacketStreamTraitTools::WriteBytes(this, reinterpret_cast<char *>(buffer), size);
}
