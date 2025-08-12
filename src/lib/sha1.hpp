#include <array>
#include <string>
#include <string_view>
#include <format>
#include <span>
#include <bit>
#include <cstdint>

class SHA1 {
private:
    static constexpr std::array<std::uint32_t, 5> INITIAL_HASH = {
        0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
    };
    
    std::array<std::uint32_t, 5> hash_state = INITIAL_HASH;
    std::uint64_t total_length = 0;
    
    static constexpr std::uint32_t left_rotate(std::uint32_t value, int shift) noexcept {
        return std::rotl(value, shift);
    }
    
    static constexpr std::uint32_t f(int t, std::uint32_t b, std::uint32_t c, std::uint32_t d) noexcept {
        if (t < 20) return (b & c) | (~b & d);
        if (t < 40) return b ^ c ^ d;
        if (t < 60) return (b & c) | (b & d) | (c & d);
        return b ^ c ^ d;
    }
    
    static constexpr std::uint32_t K(int t) noexcept {
        if (t < 20) return 0x5A827999;
        if (t < 40) return 0x6ED9EBA1;
        if (t < 60) return 0x8F1BBCDC;
        return 0xCA62C1D6;
    }
    
    void process_block(std::span<const std::uint8_t, 64> block) {
        std::array<std::uint32_t, 80> W{};
        
        // Break chunk into sixteen 32-bit big-endian words
        for (int i = 0; i < 16; ++i) {
            W[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24) |
                   (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
                   (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) |
                   (static_cast<std::uint32_t>(block[i * 4 + 3]));
        }
        
        // Extend the sixteen 32-bit words into eighty 32-bit words
        for (int i = 16; i < 80; ++i) {
            W[i] = left_rotate(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1);
        }
        
        // Initialize hash value for this chunk
        auto [a, b, c, d, e] = hash_state;
        
        // Main loop
        for (int i = 0; i < 80; ++i) {
            std::uint32_t temp = left_rotate(a, 5) + f(i, b, c, d) + e + W[i] + K(i);
            e = d;
            d = c;
            c = left_rotate(b, 30);
            b = a;
            a = temp;
        }
        
        // Add this chunk's hash to result
        hash_state[0] += a;
        hash_state[1] += b;
        hash_state[2] += c;
        hash_state[3] += d;
        hash_state[4] += e;
    }
    
public:
    void update(std::span<const std::uint8_t> data) {
        total_length += data.size();
        
        // Process complete 64-byte blocks
        while (data.size() >= 64) {
            process_block(data.subspan<0, 64>());
            data = data.subspan(64);
        }
        
        // Handle remaining bytes (will be processed in finalize)
        if (!data.empty()) {
            remaining_data.insert(remaining_data.end(), data.begin(), data.end());
        }
    }
    
    void update(std::string_view str) {
        update(std::span{reinterpret_cast<const std::uint8_t*>(str.data()), str.size()});
    }
    
    std::array<std::uint8_t, 20> finalize() {
        // Add padding
        remaining_data.push_back(0x80);  // Append '1' bit
        
        // Pad with zeros until we have 56 bytes (448 bits) in the final block
        while ((remaining_data.size() % 64) != 56) {
            remaining_data.push_back(0x00);
        }
        
        // Append original length in bits as 64-bit big-endian integer
        std::uint64_t bit_length = total_length * 8;
        for (int i = 7; i >= 0; --i) {
            remaining_data.push_back(static_cast<std::uint8_t>(bit_length >> (i * 8)));
        }
        
        // Process final block(s)
        for (size_t i = 0; i < remaining_data.size(); i += 64) {
            std::array<std::uint8_t, 64> block{};
            std::copy_n(remaining_data.begin() + i, 64, block.begin());
            process_block(block);
        }
        
        // Produce the final hash value as a 160-bit big-endian binary string
        std::array<std::uint8_t, 20> result{};
        for (int i = 0; i < 5; ++i) {
            result[i * 4] = static_cast<std::uint8_t>(hash_state[i] >> 24);
            result[i * 4 + 1] = static_cast<std::uint8_t>(hash_state[i] >> 16);
            result[i * 4 + 2] = static_cast<std::uint8_t>(hash_state[i] >> 8);
            result[i * 4 + 3] = static_cast<std::uint8_t>(hash_state[i]);
        }
        
        return result;
    }
    
    std::string hex_digest() {
        auto hash = finalize();
        std::string result;
        result.reserve(40);
        
        for (std::uint8_t byte : hash) {
            result += std::format("{:02x}", byte);
        }
        
        return result;
    }
    
    void reset() {
        hash_state = INITIAL_HASH;
        total_length = 0;
        remaining_data.clear();
    }

private:
    std::vector<std::uint8_t> remaining_data;
};

// Convenience function for one-shot hashing
std::string sha1(std::string_view input) {
    SHA1 hasher;
    hasher.update(input);
    return hasher.hex_digest();
}
