#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <format>
#include <sstream>

#include <numeric>
#include <random>
#include <set>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "lib/nlohmann/json.hpp"
#include "lib/sha1.hpp"
#include <curl/curl.h>

#include <poll.h>
#include <errno.h>

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

static size_t WriteCallback(void *contents, size_t size, size_t nmemb, std::string *userp)
{
    userp->append((char *)contents, size * nmemb);
    return size * nmemb;
}

std::string process_torrent_file(std::string &file_name)
{
    std::ifstream file = std::ifstream(file_name, std::ios::binary);
    if (!file)
    {
        std::cerr << "Error opening file\n";
        return "";
    }

    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::string buffer;
    buffer.resize(file_size);
    file.read(buffer.data(), file_size);
    file.close();

    return buffer;
}

std::string hex_to_bytes(const std::string &hex)
{
    std::string bytes;
    for (size_t i = 0; i < hex.length(); i += 2)
    {
        std::string byte_string = hex.substr(i, 2);
        uint8_t byte = (uint8_t)(std::stoi(byte_string, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::string bytes_to_hex(const unsigned char *bytes, size_t length)
{
    std::string hex;
    hex.reserve(length * 2);
    for (size_t i = 0; i < length; ++i)
        hex += std::format("{:02x}", bytes[i]);
    return hex;
}


std::string url_encode_binary(const std::string &binary_data)
{
    std::ostringstream encoded;
    encoded.fill('0');
    encoded << std::hex << std::uppercase;

    for (uint8_t c : binary_data)
    {
        encoded << '%' << std::setw(2) << static_cast<int>(c);
    }
    return encoded.str();
}

std::string get_info_hash_bytes(std::string &buffer)
{
    int info_idx = buffer.find("4:info") + strlen("4:info");
    auto info_coded = buffer.substr(info_idx, buffer.size() - info_idx - 1);
    auto hex_hash = sha1(info_coded);
    return hex_to_bytes(hex_hash);
}

std::string get_peers(std::string &buffer)
{
    json decoded_value = decode_bencoded_value(buffer);
    std::string tracker_url = decoded_value["announce"].get<std::string>();
    auto length = decoded_value["info"]["length"].get<int>();

    auto info_hash_bytes = get_info_hash_bytes(buffer);
    std::string url_encoded_hash = url_encode_binary(info_hash_bytes);
    auto url = std::format("{}?port=6881&left={}&downloaded=0&uploaded=0&compact=1&peer_id=THIS_IS_SPARTA_JKl0l&info_hash={}", tracker_url, length, url_encoded_hash);
    std::cerr << "url: " << url << '\n';
    std::string response;
    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK)
    {
        std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
    }
    json decoded_resp = decode_bencoded_value(response);
    auto peers_bin = decoded_resp["peers"].get<std::string>();
    std::string out = "";

    for (int i = 0; i < peers_bin.length(); i += 6)
    {
        uint8_t b = peers_bin[i];
        out += std::to_string((uint8_t)peers_bin[i]) + '.';
        out += std::to_string((uint8_t)peers_bin[i + 1]) + '.';
        out += std::to_string((uint8_t)peers_bin[i + 2]) + '.';
        out += std::to_string((uint8_t)peers_bin[i + 3]) + ':';

        uint16_t port = ((uint8_t)peers_bin[i + 4] << 8) | (uint8_t)peers_bin[i + 5];
        out += std::to_string(port) + '\n';
    }
    return out;
}

int handshake(std::string &peer, std::string &info_hash_bytes)
{
    //--------------[ Connect ]-------------------------------------------
    std::string peer_ip = peer.substr(0, peer.find(':'));
    int port = atoi(peer.substr(peer_ip.length() + 1).c_str());
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in peer_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr = {htonl(INADDR_ANY)},
    };
    inet_pton(AF_INET, peer_ip.c_str(), &peer_addr.sin_addr);
    connect(sock_fd, (struct sockaddr *)&peer_addr, sizeof(peer_addr));

    // 68-byte handshake
    char handshake_buf[68];
    handshake_buf[0] = 19; // length prefix
    memcpy(handshake_buf + 1, "BitTorrent protocol", 19);
    memset(handshake_buf + 20, 0, 8);                       // reserved bytes
    memcpy(handshake_buf + 28, info_hash_bytes.c_str(), 20);    // SHA1 hash
    memcpy(handshake_buf + 48, "THIS_IS_SPARTA_JKl0l", 20); // peer identifier

    ssize_t bytes_sent = write(sock_fd, handshake_buf, 68);

    char response[68];
    ssize_t bytes_read = read(sock_fd, response, 68);
    //--------------[ Connect ]-------------------------------------------

    if (bytes_read == 68 && response[0] == 19)
    {
        if (memcmp(response + 28, info_hash_bytes.c_str(), 20) == 0)
        {
            auto res = bytes_to_hex((uint8_t *)(response + 48), 20);
            std::cout << "Peer ID: " << res << '\n';
        }
        else
            sock_fd = -1;
    }

    return sock_fd;
}

enum MessageID
{
    Choke_MSG = 0x0,
    Unchoke_MSG,
    Interested_MSG,
    Not_MSGInterested,
    Have_MSG,
    Bitfield_MSG,
    Request_MSG,
    Piece_MSG,
    Cancel_MSG,
};

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
        auto buffer = process_torrent_file(file_name);
        json decoded_value = decode_bencoded_value(buffer);
        std::cout << "Tracker URL: " << decoded_value["announce"].get<std::string>() << '\n';
        std::cout << "Length: " << decoded_value["info"]["length"] << '\n';
        int info_idx = buffer.find("4:info") + strlen("4:info");
        auto info_coded = buffer.substr(info_idx, buffer.size() - info_idx - 1);
        std::cout << "Info Hash: " << sha1(info_coded) << std::endl;
        std::cout << "Piece Length: " << decoded_value["info"]["piece length"] << std::endl;

        std::string pieces_str = decoded_value["info"]["pieces"].get<std::string>();
        std::cout << "Piece Hashes: ";
        for (uint8_t byte : pieces_str)
            printf("%02x", byte);
        std::cout << '\n';
    }
    else if (command == "peers")
    {
        if (argc < 3)
        {
            std::cerr << "Usage: " << argv[0] << " peers <file>" << std::endl;
            return 1;
        }
        std::string file_name = argv[2];
        auto buffer = process_torrent_file(file_name);
        auto out = get_peers(buffer);
        std::cout << out << '\n';
    }
    else if (command == "handshake")
    {
        if (argc < 3)
        {
            std::cerr << "Usage: " << argv[0] << " handshake sample.torrent <peer_ip>:<peer_port>" << std::endl;
            return 1;
        }
        std::string file_name = argv[2];
        std::string peer = argv[3];

        auto buffer = process_torrent_file(file_name);
        json decoded_value = decode_bencoded_value(buffer);

        auto info_hash_bytes = get_info_hash_bytes(buffer);
        handshake(peer, info_hash_bytes);
    }

    else if (command == "download_piece")
    {
        constexpr uint32_t CHUNK_SIZE = 16 * 1024;
        constexpr size_t RESPONSE_BUFFER_SIZE = 1024;

        if (argc < 6)
        {
            std::cerr << "Usage: " << argv[0] << " download_piece -o out_file sample.torrent <piece_index>" << std::endl;
            return 1;
        }

        std::string out_file = argv[3];
        std::string file_name = argv[4];
        int piece_index = atoi(argv[5]);

        std::cerr << "out_file: " << out_file << '\n';
        std::cerr << "file_name: " << file_name << '\n';
        std::cerr << "piece_index: " << piece_index << '\n';

        auto buffer = process_torrent_file(file_name);
        json decoded_value = decode_bencoded_value(buffer);
        auto info_hash_bytes = get_info_hash_bytes(buffer);

        std::string peers_str = get_peers(buffer);
        std::vector<std::string> peers = std::views::split(peers_str, '\n') | std::ranges::to<std::vector<std::string>>();
        peers.pop_back();

        std::vector<int> sock_fds;
        std::vector<struct pollfd> poll_fds;
        sock_fds.reserve(peers.size());
        poll_fds.reserve(peers.size());
        for (auto &peer : peers)
        {
            int sock_fd = handshake(peer, info_hash_bytes);
            sock_fds.push_back(sock_fd);
            poll_fds.push_back({.fd = sock_fd, .events = POLLIN});
        }

        size_t standard_piece_len = decoded_value["info"]["piece length"];
        size_t total_length = decoded_value["info"]["length"];
        size_t piece_count = total_length / standard_piece_len;
        size_t used_len = piece_count * standard_piece_len;
        size_t piece_len = (piece_index < piece_count) ? standard_piece_len : (total_length > used_len ? total_length - used_len : 0);

        uint8_t *piece_buffer = (uint8_t *)malloc(piece_len);
        uint8_t response[RESPONSE_BUFFER_SIZE];

        auto handle_messages = [&](auto message_handler)
        {
            std::vector<bool> processed(sock_fds.size(), false);
            size_t processed_count = 0;

            while (processed_count < sock_fds.size())
            {
                if (poll(poll_fds.data(), poll_fds.size(), -1) < 0)
                {
                    perror("Poll Error");
                    return false;
                }

                for (size_t i = 0; i < poll_fds.size(); ++i)
                {
                    if (!(poll_fds[i].revents & POLLIN) || processed[i])
                        continue;

                    processed[i] = true;
                    processed_count++;

                    uint32_t message_len_network;
                    if (read(sock_fds[i], &message_len_network, 4) <= 0)
                        continue;

                    uint32_t message_len = ntohl(message_len_network);
                    if (read(sock_fds[i], response, message_len) <= 0)
                        continue;

                    message_handler(sock_fds[i], response[0]);
                }
            }
            return true;
        };

        // Phase 1: Handle bitfield messages
        if (!handle_messages([](int sock_fd, uint8_t msg_type) {
            if (msg_type == Bitfield_MSG)
                write(sock_fd, (char[]){0, 0, 0, 1, Interested_MSG}, 5);
        })) return -1;

        // Phase 2: Handle unchoke and send requests
        uint32_t chunk_count = (piece_len + CHUNK_SIZE - 1) / CHUNK_SIZE;

        if (!handle_messages([&](int sock_fd, uint8_t msg_type) {
            if (msg_type == Unchoke_MSG) {
                std::vector<uint32_t> chunks(chunk_count);
                std::iota(chunks.begin(), chunks.end(), 0);
                
                std::random_device rd;
                std::mt19937 g(rd());
                std::shuffle(chunks.begin(), chunks.end(), g);

                uint32_t piece_index_network = htonl(piece_index);
                uint32_t msg_len_network = htonl(13);

                for (uint32_t chunk_idx : chunks)
                {
                    uint32_t begin = htonl(chunk_idx * CHUNK_SIZE);
                    uint32_t len = htonl(std::min(CHUNK_SIZE, (uint32_t)(piece_len - chunk_idx * CHUNK_SIZE)));

                    write(sock_fd, &msg_len_network, 4);
                    write(sock_fd, (char[]){Request_MSG}, 1);
                    write(sock_fd, &piece_index_network, 4);
                    write(sock_fd, &begin, 4);
                    write(sock_fd, &len, 4);
                }
        } })) return -1;

        std::set<uint32_t> offsets;
        while (offsets.size() < chunk_count)
        {
            int res = poll(poll_fds.data(), poll_fds.size(), -1);
            if (res < 0)
            {
                perror("Poll Error");
                return -1;
            }

            for (auto pfd : poll_fds)
            {
                if (not(pfd.revents & POLLIN))
                    continue;

                int sock_fd = pfd.fd;

                uint32_t message_len_network;
                read(sock_fd, &message_len_network, 4);
                uint32_t message_len = ntohl(message_len_network);

                uint8_t rec_id;
                uint32_t rec_piecie_idx;
                uint32_t byte_offset_network;
                read(sock_fd, &rec_id, 1);
                read(sock_fd, &rec_piecie_idx, 4);
                read(sock_fd, &byte_offset_network, 4);
                uint32_t byte_offset = ntohl(byte_offset_network);

                if (offsets.find(byte_offset) != offsets.end())
                {
                    std::cerr << "Duplicate block, skipping\n";
                    size_t block_len = message_len - 9;
                    uint8_t discard_buffer[256];
                    size_t discarded = 0;
                    while (discarded < block_len)
                    {
                        discarded += read(sock_fd, discard_buffer,
                                          std::min(sizeof(discard_buffer), block_len - discarded));
                    }
                    continue;
                }
                offsets.insert(byte_offset);

                for (auto fd : sock_fds)
                {
                    if (fd != sock_fd)
                    {
                        uint32_t cancel_len = htonl(13);
                        write(fd, &cancel_len, 4);
                        write(fd, (char[]){Cancel_MSG}, 1);
                        write(fd, &rec_piecie_idx, 4);
                        write(fd, &byte_offset_network, 4);
                        write(fd, &message_len_network, 4);
                    }
                }

                size_t block_len = message_len - 9;
                size_t block_bytes_read = 0;
                while (block_bytes_read < block_len)
                    block_bytes_read += read(sock_fd, piece_buffer + byte_offset + block_bytes_read, block_len - block_bytes_read);
            }
        }

        std::ofstream file = std::ofstream(out_file, std::ios::binary);
        if (file)
        {
            file.write((const char *)piece_buffer, piece_len);
            file.close();
        }
    }

    else
    {
        std::cerr << "unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}
