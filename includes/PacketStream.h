#ifndef PACKET_STREAM_H // !PACKET_STREAM_H
#define PACKET_STREAM_H

// PACKET_STREAM_NETWORK_ENDIAN: Serialize with network endian

#include <vector>
#include <stdexcept>

class PacketStream;

struct PacketStreamTraitTools
{
    template <typename any_t>
    inline static any_t ReadTrivial(PacketStream *self);

    template <typename any_t>
    inline static size_t WriteTrivial(PacketStream *self, const any_t &data);

    inline static char *ReadBytesRef(PacketStream *self, size_t size);
    inline static void ReadBytes(PacketStream *self, char *buffer, size_t size);

    inline static size_t WriteBytes(PacketStream *self, char *buffer, size_t size);
};

template <typename any_t>
struct PacketStreamTrait;

class PacketStream
{
public:
    void Reserve(size_t size);

    void Clear();

    std::vector<char> &Buffer();

    ptrdiff_t Tell() const;

    bool Seek(ptrdiff_t offset, int origin = SEEK_SET);

    template <typename integer_t = int32_t>
    integer_t Push();

    template <typename integer_t>
    void Pop(integer_t position);

    template <typename any_t>
    any_t Read();
    template <typename any_t>
    void Read(any_t &data);

    template <typename any_t>
    size_t Write(const any_t &data);

    void ReadBytes(void *buffer, size_t size);
    char *ReadBytesRef(size_t size);

    void WriteBytes(void *buffer, size_t size);

    template <typename any_t>
    PacketStream &operator>>(any_t &data);

    template <typename any_t>
    PacketStream &operator<<(const any_t &data);

private:
    friend struct PacketStreamTraitTools;
    template <typename any_t>
    friend struct PacketStreamTrait;

    ptrdiff_t m_index = 0;
    std::vector<char> m_buffer;
};

struct PacketSerializable
{
    virtual void DeSerialize(PacketStream *self) = 0;

    virtual void Serialize(PacketStream *self) const = 0;
};

// ==============================PacketStreamTraitTools Implementaion==============================
#ifndef PACKET_STREAM_NETWORK_ENDIAN
template <typename any_t>
any_t PacketStreamTraitTools::ReadTrivial(PacketStream *self)
{
    if (self->m_index + sizeof(any_t) > self->m_buffer.size())
        throw std::runtime_error("Read out of range");

    auto result = *reinterpret_cast<any_t *>(self->m_buffer.data() + self->m_index);
    self->m_index += sizeof(any_t);

    return result;
}

template <typename any_t>
size_t PacketStreamTraitTools::WriteTrivial(PacketStream *self, const any_t &data)
{
    auto begin = reinterpret_cast<char *>(const_cast<any_t *>(&data));
    auto end = begin + sizeof(any_t);

    if (self->m_buffer.size() <= static_cast<size_t>(self->m_index))
        self->m_buffer.insert(self->m_buffer.begin() + self->m_index, begin, end);
    else
        memcpy(self->m_buffer.data() + self->m_index, begin, sizeof(any_t));
    self->m_index += sizeof(any_t);

    return self->m_buffer.size();
}

char *PacketStreamTraitTools::ReadBytesRef(PacketStream *self, size_t size)
{
    if (self->m_index + size > self->m_buffer.size())
        throw std::runtime_error("Read out of range");

    auto result = self->m_buffer.data() + self->m_index;
    self->m_index += size;

    return result;
}
void PacketStreamTraitTools::ReadBytes(PacketStream *self, char *buffer, size_t size)
{
    if (self->m_index + size > self->m_buffer.size())
        throw std::runtime_error("Read out of range");

    memcpy(buffer, self->m_buffer.data() + self->m_index, size);
    self->m_index += size;
}

size_t PacketStreamTraitTools::WriteBytes(PacketStream *self, char *buffer, size_t size)
{
    if (self->m_buffer.size() <= static_cast<size_t>(self->m_index))
        self->m_buffer.insert(self->m_buffer.begin() + self->m_index, buffer, buffer + size);
    else
        memcpy(self->m_buffer.data() + self->m_index, buffer, size);
    self->m_index += size;

    return self->m_index;
}
#else
#endif

// ==============================PacketStreamTrait Implementaion==============================
template <typename any_t>
struct PacketStreamTrait : PacketStreamTraitTools
{
    inline static any_t Read(PacketStream *self)
    {
        static_assert(std::is_trivial_v<any_t> || std::is_base_of_v<PacketSerializable, any_t>, "Custom data type is not trivial or serializable.");

        if constexpr (std::is_trivial_v<any_t>)
            return ReadTrivial<any_t>(self);
        else if constexpr (std::is_base_of_v<PacketSerializable, any_t>)
        {
            any_t result{};

            result.DeSerialize(self);

            return result;
        }
    }

    inline static size_t Write(PacketStream *self, const any_t &data)
    {
        static_assert(std::is_trivial_v<any_t> || std::is_base_of_v<PacketSerializable, any_t>, "Custom data type is not trivial or serializable.");

        if constexpr (std::is_trivial_v<any_t>)
            return WriteTrivial(self, data);
        else if constexpr (std::is_base_of_v<PacketSerializable, any_t>)
        {
            data.Serialize(self);

            return self->m_buffer.size();
        }
    }
};

template <>
struct PacketStreamTrait<int32_t> : PacketStreamTraitTools
{
    inline static int32_t Read(PacketStream *self) { return ReadTrivial<int32_t>(self); }

    inline static size_t Write(PacketStream *self, int32_t data) { return WriteTrivial<int32_t>(self, data); }
};

template <>
struct PacketStreamTrait<int64_t> : PacketStreamTraitTools
{
    inline static int64_t Read(PacketStream *self) { return ReadTrivial<int64_t>(self); }

    inline static size_t Write(PacketStream *self, int64_t data) { return WriteTrivial<int64_t>(self, data); }
};

template <int dimension>
struct PacketStreamTrait<char[dimension]> : PacketStreamTraitTools
{
    inline static const char *Read(PacketStream *self) { return ReadBytesRef(self, ReadTrivial<int>(self)); }

    inline static size_t Write(PacketStream *self, const char (&data)[dimension]) { return (WriteTrivial(self, dimension), WriteBytes(self, const_cast<char *>(reinterpret_cast<const char *>(data)), dimension)); }
};

template <>
struct PacketStreamTrait<const char *> : PacketStreamTraitTools
{
    inline static const char *Read(PacketStream *self) { return ReadBytesRef(self, ReadTrivial<int>(self)); }

    inline static size_t Write(PacketStream *self, const char *data)
    {
        int size = static_cast<int>(strlen(data)) + 1;

        WriteTrivial(self, size);

        return WriteBytes(self, const_cast<char *>(data), size);
    }
};

template <>
struct PacketStreamTrait<char *> : PacketStreamTraitTools
{
    inline static char *Read(PacketStream *self) { return ReadBytesRef(self, ReadTrivial<int>(self)); }

    inline static size_t Write(PacketStream *self, char *data)
    {
        int size = static_cast<int>(strlen(data)) + 1;

        WriteTrivial(self, size);

        return WriteBytes(self, data, size);
    }
};

template <>
struct PacketStreamTrait<std::string> : PacketStreamTraitTools
{
    inline static std::string Read(PacketStream *self)
    {
        auto size = ReadTrivial<int32_t>(self);

        std::string result(size, 0);
        ReadBytes(self, result.data(), result.size());

        return result;
    }

    inline static size_t Write(PacketStream *self, const std::string &data)
    {
        WriteTrivial(self, static_cast<int32_t>(data.size()));

        return WriteBytes(self, const_cast<char *>(data.data()), data.size());
    }
};

template <>
struct PacketStreamTrait<std::string_view> : PacketStreamTraitTools
{
    inline static std::string_view Read(PacketStream *self)
    {
        auto size = ReadTrivial<int32_t>(self);

        return {ReadBytesRef(self, size), static_cast<size_t>(size)};
    }

    inline static size_t Write(PacketStream *self, const std::string_view &data)
    {
        WriteTrivial(self, static_cast<int32_t>(data.size()));

        return WriteBytes(self, const_cast<char *>(data.data()), data.size());
    }
};

// ==============================PacketStream Implementaion==============================
template <typename integer_t>
integer_t PacketStream::Push()
{
    auto result = Tell();

    Write<integer_t>(0);

    return static_cast<integer_t>(result);
}

template <typename integer_t>
void PacketStream::Pop(integer_t position)
{
    auto origin = Tell();

    if (!Seek(position, SEEK_SET))
        return;

    Write<integer_t>(static_cast<integer_t>(origin));
    Seek(origin, SEEK_SET);
}

template <typename any_t>
any_t PacketStream::Read()
{
    return PacketStreamTrait<any_t>::Read(this);
}
template <typename any_t>
void PacketStream::Read(any_t &data)
{
    data = PacketStreamTrait<any_t>::Read(this);
}

template <typename any_t>
size_t PacketStream::Write(const any_t &data)
{
    return PacketStreamTrait<any_t>::Write(this, data);
}

template <typename any_t>
PacketStream &PacketStream::operator>>(any_t &data)
{
    data = PacketStreamTrait<any_t>::Read(this);

    return *this;
}

template <typename any_t>
PacketStream &PacketStream::operator<<(const any_t &data)
{
    PacketStreamTrait<any_t>::Write(this, data);

    return *this;
}

#endif // !PACKET_STREAM_H