#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <format>
#include <sstream>
#include <thread>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "lib/nlohmann/json.hpp"
#include "lib/sha1.hpp"
#include <curl/curl.h>

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
std::string url_decode(const std::string &encoded)
{
    std::string decoded;
    decoded.reserve(encoded.size());

    for (char *chr = (char *)encoded.data(); *chr; chr++)
    {
        if ((*chr) == '%')
        {
            std::stringstream hex_stream;
            hex_stream << *(chr + 1);
            hex_stream << *(chr + 2);
            int hex_value;
            if (hex_stream >> std::hex >> hex_value)
            {
                decoded += (char)(hex_value);
                chr += 2;
            }
            else
                decoded += (*chr);
        }
        else
            decoded += (*chr);
    }

    return decoded;
}

std::string get_info_hash_bytes(std::string &buffer)
{
    int info_idx = buffer.find("4:info") + strlen("4:info");
    auto info_coded = buffer.substr(info_idx, buffer.size() - info_idx - 1);
    auto hex_hash = sha1(info_coded);
    return hex_to_bytes(hex_hash);
}

std::string get_peers(std::string &tracker_url, std::string &info_hash_bytes, int length=1)
{
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
    return out.substr(0, out.length()-1);
}
std::string get_peers(std::string &buffer)
{
    json decoded_value = decode_bencoded_value(buffer);
    std::string tracker_url = decoded_value["announce"].get<std::string>();
    int length = decoded_value["info"]["length"].get<int>();
    std::string info_hash_bytes = get_info_hash_bytes(buffer);
    return get_peers(tracker_url, info_hash_bytes, length);
};

void hexdump(const void *data, size_t size)
{
    const unsigned char *byte = (const unsigned char *)data;
    char buffer[4096];
    size_t buf_used = 0;
    size_t i, j;

    for (i = 0; i < size; i += 16) {
        char line[80];  // A line won't exceed 80 chars
        int len = snprintf(line, sizeof(line), "%08zx  ", i);

        // Hex part
        for (j = 0; j < 16; j++) {
            if (i + j < size)
                len += snprintf(line + len, sizeof(line) - len, "%02x ", byte[i + j]);
            else
                len += snprintf(line + len, sizeof(line) - len, "   ");
            if (j == 7)
                len += snprintf(line + len, sizeof(line) - len, " ");
        }

        // ASCII part
        len += snprintf(line + len, sizeof(line) - len, " |");
        for (j = 0; j < 16 && i + j < size; j++) {
            unsigned char ch = byte[i + j];
            len += snprintf(line + len, sizeof(line) - len, "%c", isprint(ch) ? ch : '.');
        }
        len += snprintf(line + len, sizeof(line) - len, "|\n");

        // Append line to buffer
        if (buf_used + len < sizeof(buffer)) {
            memcpy(buffer + buf_used, line, len);
            buf_used += len;
        } else {
            // Prevent buffer overflow
            break;
        }
    }

    // Null-terminate and print once
    buffer[buf_used] = '\0';
    fprintf(stderr,
           "Idx       | Hex                                             | ASCII\n"
           "----------+-------------------------------------------------+-----------------\n"
           "%s",
           buffer);
}


struct PeerInfo
{
    int sock_fd = -1;
    uint8_t ut_metadata = 0;
    bool extension = false;
};

PeerInfo handshake(std::string &peer, std::string &info_hash_bytes, bool extension = false)
{
    //--------------[ Connect ]-------------------------------------------
    std::string peer_ip = peer.substr(0, peer.find(':'));
    int port = atoi(peer.substr(peer_ip.length() + 1).c_str());
    PeerInfo res;
    res.sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in peer_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr = {htonl(INADDR_ANY)},
    };
    inet_pton(AF_INET, peer_ip.c_str(), &peer_addr.sin_addr);
    connect(res.sock_fd, (struct sockaddr *)&peer_addr, sizeof(peer_addr));

    // 68-byte handshake
    char handshake_buf[68];
    handshake_buf[0] = 19; // length prefix
    memcpy(handshake_buf + 1, "BitTorrent protocol", 19);
    memset(handshake_buf + 20, 0, 8);                       // reserved bytes
    memcpy(handshake_buf + 28, info_hash_bytes.c_str(), 20);    // SHA1 hash
    memcpy(handshake_buf + 48, "THIS_IS_SPARTA_JKl0l", 20); // peer identifier

    if (extension)
        handshake_buf[25] = 0x10;

    ssize_t bytes_sent = write(res.sock_fd, handshake_buf, 68);

    char response[68];
    ssize_t bytes_read = read(res.sock_fd, response, 68);
    //--------------[ Connect ]-------------------------------------------

    if (bytes_read == 68 && response[0] == 19)
    {
        if (memcmp(response + 28, info_hash_bytes.c_str(), 20) == 0)
        {
            auto peer_id = bytes_to_hex((uint8_t *)(response + 48), 20);
            std::cout << "Peer ID: " << peer_id << '\n';
            if (response[25] == 0x10)
            {
                std::cerr << "---------[ Extension Supported ]---------" << '\n';
                std::string out = "d1:md11:ut_metadatai1e6:ut_pexi2ee1:pi6881ee";
                uint32_t len = out.length() + /* message id */ 1 + /* ext message id */ 1;
                len = htonl(len);
                write(res.sock_fd, &len, 4);
                write(res.sock_fd, (char[])20, 1);
                write(res.sock_fd, (char[])0, 1);
                write(res.sock_fd, out.c_str(), out.length());

                //--[ BitField]--------------------
                uint32_t message_len;
                read(res.sock_fd, &message_len, 4);
                message_len = ntohl(message_len);
                read(res.sock_fd, response, message_len);

                //--[ Receive Extension Handshake ]--------------------
                read(res.sock_fd, &message_len, 4);
                message_len = ntohl(message_len);
                read(res.sock_fd, response, 2); // Message ID and Ext Message ID
                message_len -= 2;

                std::string bufstr("", message_len);
                size_t bytes_read = read(res.sock_fd, bufstr.data(), message_len);
                
                auto decoded_value = decode_bencoded_value(bufstr);
                uint8_t ut_metadata = decoded_value["m"]["ut_metadata"].get<uint8_t>();
                std::cout << "Peer Metadata Extension ID: " << (int)ut_metadata << '\n';

                res.ut_metadata = ut_metadata ;
                res.extension = true;
            }
        }
        else
            res.sock_fd = -1;
    }
    return res;
}


std::vector<int> get_peers_connections(std::string &buffer)
{
    auto info_hash_bytes = get_info_hash_bytes(buffer);
    std::string peers_str = get_peers(buffer);
    std::vector<std::string> peers;
    for (auto peer: std::views::split(peers_str, '\n'))
    	peers.push_back({peer.begin(), peer.end()});

    std::vector<int> sockets;
    sockets.reserve(peers.size());
    std::vector<std::thread> threads;
    threads.reserve(peers.size());
    for (auto &peer : peers)
    {
        threads.emplace_back([&]() { 
            sockets.push_back(handshake(peer, info_hash_bytes).sock_fd);
        });
    }
    for (auto &thread : threads)
        thread.join();
    return sockets;
}

constexpr uint32_t CHUNK_SIZE = 16 * 1024;
constexpr size_t RESPONSE_BUFFER_SIZE = 1024;

void download_piece(int sock_fd, uint8_t *piece_buffer, size_t piece_size, int piece_index)
{
    uint8_t response[RESPONSE_BUFFER_SIZE];

    // Phase 1: Handle bitfield messages
    uint32_t message_len_network;
    read(sock_fd, &message_len_network, 4);
    uint32_t message_len = ntohl(message_len_network);
    read(sock_fd, response, message_len);
    
    if (response[0] == Bitfield_MSG)
        write(sock_fd, (char[]){0, 0, 0, 1, Interested_MSG}, 5); 
    

    // Phase 2: Handle unchoke and send requests
    uint32_t chunk_count = (piece_size + CHUNK_SIZE - 1) / CHUNK_SIZE;
    read(sock_fd, &message_len_network, 4);
    message_len = ntohl(message_len_network);
    read(sock_fd, response, message_len);
    if (response[0] == Unchoke_MSG)
    {
        uint32_t piece_index_network = htonl(piece_index);
        uint32_t msg_len_network = htonl(13);

        for (int chunk_idx = 0; chunk_idx < chunk_count; ++chunk_idx)
        {
            uint32_t begin = htonl(chunk_idx * CHUNK_SIZE);
            uint32_t len = htonl(std::min(CHUNK_SIZE, (uint32_t)(piece_size - chunk_idx * CHUNK_SIZE)));

            write(sock_fd, &msg_len_network, 4);
            write(sock_fd, (char[]){Request_MSG}, 1);
            write(sock_fd, &piece_index_network, 4);
            write(sock_fd, &begin, 4);
            write(sock_fd, &len, 4);
        }
    }

    // Phase 3: Download chunks
    for (int chunk_idx = 0; chunk_idx < chunk_count; ++chunk_idx)
    {
        read(sock_fd, &message_len_network, 4);
        message_len = ntohl(message_len_network);
        uint8_t rec_id;
        uint32_t rec_piecie_idx;
        uint32_t byte_offset_network;
        read(sock_fd, &rec_id, 1);
        read(sock_fd, &rec_piecie_idx, 4);
        read(sock_fd, &byte_offset_network, 4);
        uint32_t byte_offset = ntohl(byte_offset_network);

        size_t block_len = message_len - 9;
        size_t block_bytes_read = 0;
        while (block_bytes_read < block_len)
            block_bytes_read += read(sock_fd, piece_buffer + byte_offset + block_bytes_read, block_len - block_bytes_read);
    }
    close(sock_fd);    
}

PeerInfo magnet_handshake(int argc, char* argv[])
{
    if (argc < 3)
    {
        std::cerr << "Usage: " << argv[0] << " magnet_handshake <magnet-link>" << std::endl;
        return {};
    }
    std::string magnet_link = argv[2];
    auto pos = magnet_link.find("xt=urn:btih:") + strlen("xt=urn:btih:");
    std::string info_hash = magnet_link.substr(pos, 40);
    pos = magnet_link.find("tr=") + strlen("tr=");
    std::string tracker_url = url_decode(magnet_link.substr(pos, magnet_link.length() - pos));

    std::cout << "Info Hash: " << info_hash << '\n';
    std::cout << "Tracker URL: " << tracker_url << '\n';

    std::string bytes_info_hash = hex_to_bytes(info_hash);
    std::string peers = get_peers(tracker_url, bytes_info_hash);
    return handshake(peers, bytes_info_hash, true);
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
        size_t standard_piece_len = decoded_value["info"]["piece length"];
        size_t total_size = decoded_value["info"]["length"];
        size_t piece_count = total_size / standard_piece_len;
        size_t used_len = piece_count * standard_piece_len;
        size_t piece_size = (piece_index < piece_count) ? standard_piece_len : (total_size > used_len ? total_size - used_len : 0);

        uint8_t *piece_buffer = (uint8_t *)malloc(piece_size);

        std::vector<int> sockets = get_peers_connections(buffer);
        download_piece(sockets.front(), piece_buffer, piece_size, piece_index);

        std::ofstream file = std::ofstream(out_file, std::ios::binary);
        if (file)
        {
            file.write((const char *)piece_buffer, piece_size);
            file.close();
        }
    }

    else if (command == "download")
    {
        if (argc < 5)
        {
            std::cerr << "Usage: " << argv[0] << " download -o out_file sample.torrent" << std::endl;
            return 1;
        }

        std::string out_file = argv[3];
        std::string file_name = argv[4];
        
        auto buffer = process_torrent_file(file_name);
        json decoded_value = decode_bencoded_value(buffer);
        size_t standard_piece_size = decoded_value["info"]["piece length"];
        size_t total_size = decoded_value["info"]["length"];
        int piece_count = (total_size) / standard_piece_size;
        size_t used_len = piece_count * standard_piece_size;

        uint8_t *file_buffer = (uint8_t *)malloc(total_size);
        
        for (int piece_index = 0; piece_index <= piece_count;)
        {
            std::vector<int> sockets = get_peers_connections(buffer);
            std::vector<std::thread> threads;
            threads.reserve(sockets.size());
            for (auto sock_fd : sockets)
            {
                if (piece_index > piece_count)
                    break;

                size_t piece_size = (piece_index < piece_count) ? standard_piece_size : (total_size > used_len ? total_size - used_len : 0);
                uint8_t *piece_buffer = file_buffer + (piece_index * standard_piece_size);
                threads.emplace_back(download_piece, sock_fd, piece_buffer, piece_size, piece_index++);
            }
            for (auto &thread : threads)
                thread.join();
        }

        std::ofstream file = std::ofstream(out_file, std::ios::binary);
        if (file)
        {
            file.write((const char *)file_buffer, total_size);
            file.close();
        }
    }
    else if (command == "magnet_parse")
    {
        if (argc < 3)
        {
            std::cerr << "Usage: " << argv[0] << " magnet_parse <magnet-link>" << std::endl;
            return 1;
        }

        std::string magnet_link = argv[2];
        auto pos = magnet_link.find("xt=urn:btih:") + strlen("xt=urn:btih:");

        std::string info_hash = magnet_link.substr(pos, 40);
        pos = magnet_link.find("tr=") + strlen("tr=");
        std::string url = magnet_link.substr(pos, magnet_link.length() - pos);

        std::cout << "Info Hash: " << info_hash << '\n';
        std::cout << "Tracker URL: " << url_decode(url) << '\n';
    }
    else if (command == "magnet_handshake")
    {
        magnet_handshake(argc, argv);
    }
    else if (command == "magnet_info")
    {
        PeerInfo peer = magnet_handshake(argc, argv);
        
        std::string payload = "d8:msg_typei0e5:piecei0ee";
        uint32_t len = payload.length()+2;
        len = htonl(len);
        write(peer.sock_fd, &len, 4);
        write(peer.sock_fd, (char[])20, 1);
        write(peer.sock_fd, &peer.ut_metadata, 1);
        write(peer.sock_fd, payload.c_str(), payload.length());
    }

    else
    {
        std::cerr << "unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}
