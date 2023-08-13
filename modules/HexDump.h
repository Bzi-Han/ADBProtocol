#ifndef HEX_DUMP_H //! HEX_DUMP_H
#define HEX_DUMP_H

#include <iostream>
#include <sstream>
#include <type_traits>
#include <vector>
#include <mutex>

/**
 * @class HexDump
 * @brief HexDump
 */
class HexDump
{
public:
    /**
     * @name print
     * @brief 打印指定大小的缓冲区的值集合
     *
     * @param buffer 要打印的缓冲区指针
     * @param size 要打印的范围大小
     *
     * @return void
     */
    static void print(const void *buffer, size_t size)
    {
        static char serialTable[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
        static std::vector<char> serialBuffer;
        static std::stringstream renderBuffer;
        static std::mutex printMutex;

        const uint32_t rowSize = 16;
        auto bufferPointer = reinterpret_cast<const uint8_t *>(buffer);
        auto row = size / rowSize;
        auto remain = static_cast<uint8_t>(size % rowSize);

        auto fixedPrintHex = [](std::conditional_t<sizeof(uint32_t) == sizeof(void *), uint32_t, uint64_t> value, uint8_t fixedSize)
        {
            serialBuffer.clear();

            while (0 < value)
            {
                serialBuffer.push_back(serialTable[value % 16]);
                value /= 16;
            }

            auto count = fixedSize - serialBuffer.size();
            for (uint32_t i = 0; i < count; i++)
                serialBuffer.push_back('0');

            for (size_t i = serialBuffer.size(); i > 0; i--)
                renderBuffer << serialBuffer[i - 1];
        };

        auto printRow = [&](size_t index, uint8_t length)
        {
            fixedPrintHex(index * rowSize, sizeof(void *));

            renderBuffer << "        ";
            for (uint32_t j = 0; j < length; j++)
            {
                if (0 != j)
                    renderBuffer << " ";

                fixedPrintHex(bufferPointer[index * rowSize + j], 2);
            }
            for (uint32_t j = 0; j < rowSize - length; j++)
                renderBuffer << "   ";

            renderBuffer << "        ";
            for (uint32_t j = 0; j < length; j++)
            {
                if (32 < bufferPointer[index * rowSize + j] && 127 > bufferPointer[index * rowSize + j])
                    renderBuffer << bufferPointer[index * rowSize + j];
                else
                    renderBuffer << ".";
            }
            for (uint32_t j = 0; j < rowSize - length; j++)
                renderBuffer << " ";

            renderBuffer << std::endl;
        };

        {
            std::unique_lock<std::mutex> locker(printMutex);

            renderBuffer.seekp(0, std::ios_base::beg);

            for (size_t i = 0; i < row; i++)
                printRow(i, rowSize);

            if (0 != remain)
                printRow(row, remain);

            std::cout << renderBuffer.view().substr(0, renderBuffer.tellp());
        }
    }

private:
    explicit HexDump(){};
    virtual ~HexDump(){};
};

#endif //! HEX_DUMP_H