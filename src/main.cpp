#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>
#include <fstream>

#include "lib/nlohmann/json.hpp"
#include "lib/sha1.hpp"

using json = nlohmann::json;

int default_offset;

json decode_bencoded_value(const std::string& encoded_value, int *offset = &default_offset)
{
    if (std::isdigit(encoded_value[0]))
    {
        // Example: "5:hello" -> "hello"
        size_t colon_index = encoded_value.find(':');
        if (colon_index != std::string::npos)
        {
            std::string number_string = encoded_value.substr(0, colon_index);
            int64_t number = std::atoll(number_string.c_str());
            *offset = colon_index + 1 + number;
            std::string str = encoded_value.substr(colon_index + 1, number);
            return json(str);
        }
        else
        {
            throw std::runtime_error("Invalid encoded value: " + encoded_value);
        }
    }
    else if (encoded_value[0] == 'i')
    {
        *offset = encoded_value.find('e')+1;
        auto res = encoded_value.substr(1, *offset);
        return json(std::atoll(res.c_str()));
    }
    else if (encoded_value[0] == 'l')
    {
        auto res = json::array({});
        int beg = 1;
        int end = 0;
        while (beg + 1 < encoded_value.length())
        {
            if (encoded_value[beg] == 'e')
                break;
            auto str = encoded_value.substr(beg);
            auto e = decode_bencoded_value(str, &end);
            if (end == -1)
                break;

            res.push_back(e);
            beg += end;
        }
        *offset = beg + 1;
        return res;
    }
    else if (encoded_value[0] == 'd')
    {
        auto res = json({});
        int beg = 1;
        int end = 0;
        while (beg + 1 < encoded_value.length())
        {
            if (encoded_value[beg] == 'e')
                break;
            auto key_str = encoded_value.substr(beg);
            auto key = decode_bencoded_value(key_str, &end);
            if (end == -1)
                break;

            beg += end;

            if (encoded_value[beg] == 'e')
                break;
            auto val_str = encoded_value.substr(beg);
            auto value = decode_bencoded_value(val_str, &end);
            if (end == -1)
                break;

            beg += end;
            res[key] = value;
        }
        *offset = beg + 1;
        return res;
    }
    else
    {
        throw std::runtime_error("Unhandled encoded value: " + encoded_value);
    }
}

int main(int argc, char* argv[])
{
    // Flush after every std::cout / std::cerr
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " decode <encoded_value>" << std::endl;
        return 1;
    }

    std::string command = argv[1];

    if (command == "decode")
    {
        if (argc < 3)
        {
            std::cerr << "Usage: " << argv[0] << " decode <encoded_value>" << std::endl;
            return 1;
        }
        // You can use print statements as follows for debugging, they'll be visible when running tests.
        std::cerr << "Logs from your program will appear here!" << std::endl;

        std::string encoded_value = argv[2];
        json decoded_value = decode_bencoded_value(encoded_value);
        std::cout << decoded_value.dump() << std::endl;
    }
    else if (command == "info")
        {
            if (argc < 3)
            {
                std::cerr << "Usage: " << argv[0] << " info <file>" << std::endl;
                return 1;
            }

            std::string file_name = argv[2];
            std::ifstream file = std::ifstream(file_name, std::ios::binary);
            if (!file)
            {
                std::cerr << "Error opening file\n";
                return 1;
            }

            file.seekg(0, std::ios::end);
            size_t file_size = file.tellg();
            file.seekg(0, std::ios::beg);

            std::string buffer;
            buffer.resize(file_size);
            file.read(buffer.data(), file_size);
            file.close();

            json decoded_value = decode_bencoded_value(buffer);
            std::cout << "Tracker URL: " << decoded_value["announce"].get<std::string>() << '\n';
            std::cout << "Length: " << decoded_value["info"]["length"] << '\n';
            int info_idx = buffer.find("4:info") + strlen("4:info");
            auto info_coded = buffer.substr(info_idx, buffer.size()-info_idx-1);
            std::cout << "Info Hash: " << sha1(info_coded) << std::endl;
            std::cout << "Piece Length: " << decoded_value["info"]["piece length"] << std::endl;

            std::string pieces_str = decoded_value["info"]["pieces"].get<std::string>();
            std::cout << "Piece Hashes: ";
            for (uint8_t byte : pieces_str)
                printf("%02x", byte);
            std::cout << '\n';
            
        }
    else
    {
        std::cerr << "unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}
