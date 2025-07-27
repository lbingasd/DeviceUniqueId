#pragma once
#include <string>
#include <cstring>
#include <sstream>
#include <iomanip>

class MD5
{
public:
    MD5() { reset(); }
    MD5& update(const unsigned char* input, size_t length) { update_(input, length); return *this; }
    MD5& update(const std::string& str) { return update((const unsigned char*)str.c_str(), str.size()); }
    std::string hexdigest() {
        unsigned char digest[16];
        finalize(digest);
        std::ostringstream oss;
        for (int i = 0; i < 16; ++i) oss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
        return oss.str();
    }
    static std::string md5(const std::string& str) { MD5 md; md.update(str); return md.hexdigest(); }
private:
    void reset() {
        finalized = false; count[0] = count[1] = 0;
        state[0]=0x67452301ul; state[1]=0xefcdab89ul; state[2]=0x98badcfeul; state[3]=0x10325476ul;
    }
    void update_(const unsigned char* input, size_t length) {
        size_t i, index, partLen;
        if (finalized) return;
        index = unsigned((count[0] >> 3) & 0x3F);
        if ((count[0] += (uint32_t)length << 3) < ((uint32_t)length << 3)) count[1]++;
        count[1] += ((uint32_t)length >> 29);
        partLen = 64 - index;
        if (length >= partLen) {
            memcpy(&buffer[index], input, partLen); transform(buffer);
            for (i = partLen; i + 63 < length; i += 64) transform(&input[i]);
            index = 0;
        } else { i = 0; }
        memcpy(&buffer[index], &input[i], length - i);
    }
    void finalize(unsigned char digest[16]) {
        if (finalized) return;
        unsigned char bits[8];
        encode(count, bits, 8);
        size_t index = (count[0] >> 3) & 0x3f;
        size_t padLen = (index < 56) ? (56 - index) : (120 - index);
        static unsigned char PADDING[64] = { 0x80 };
        update(PADDING, padLen);
        update(bits, 8);
        encode(state, digest, 16);
        finalized = true;
    }
    void transform(const unsigned char block[64]) {
        uint32_t a=state[0],b=state[1],c=state[2],d=state[3],x[16];
        decode(block, x, 64);
        #define F(x,y,z) ((x&y)|(~x&z))
        #define G(x,y,z) ((x&z)|(y&~z))
        #define H(x,y,z) (x^y^z)
        #define I(x,y,z) (y^(x|~z))
        #define ROTATE_LEFT(x,n) ((x<<n)|(x>>(32-n)))
        #define FF(a,b,c,d,x,s,ac) {a+=F(b,c,d)+x+ac;a=ROTATE_LEFT(a,s);a+=b;}
        #define GG(a,b,c,d,x,s,ac) {a+=G(b,c,d)+x+ac;a=ROTATE_LEFT(a,s);a+=b;}
        #define HH(a,b,c,d,x,s,ac) {a+=H(b,c,d)+x+ac;a=ROTATE_LEFT(a,s);a+=b;}
        #define II(a,b,c,d,x,s,ac) {a+=I(b,c,d)+x+ac;a=ROTATE_LEFT(a,s);a+=b;}
        FF(a,b,c,d,x[ 0], 7,0xd76aa478ul); FF(d,a,b,c,x[ 1],12,0xe8c7b756ul); FF(c,d,a,b,x[ 2],17,0x242070dbul); FF(b,c,d,a,x[ 3],22,0xc1bdceeeul);
        FF(a,b,c,d,x[ 4], 7,0xf57c0faful); FF(d,a,b,c,x[ 5],12,0x4787c62aul); FF(c,d,a,b,x[ 6],17,0xa8304613ul); FF(b,c,d,a,x[ 7],22,0xfd469501ul);
        FF(a,b,c,d,x[ 8], 7,0x698098d8ul); FF(d,a,b,c,x[ 9],12,0x8b44f7aful); FF(c,d,a,b,x[10],17,0xffff5bb1ul); FF(b,c,d,a,x[11],22,0x895cd7beul);
        FF(a,b,c,d,x[12], 7,0x6b901122ul); FF(d,a,b,c,x[13],12,0xfd987193ul); FF(c,d,a,b,x[14],17,0xa679438eul); FF(b,c,d,a,x[15],22,0x49b40821ul);
        GG(a,b,c,d,x[ 1], 5,0xf61e2562ul); GG(d,a,b,c,x[ 6], 9,0xc040b340ul); GG(c,d,a,b,x[11],14,0x265e5a51ul); GG(b,c,d,a,x[ 0],20,0xe9b6c7aaul);
        GG(a,b,c,d,x[ 5], 5,0xd62f105dul); GG(d,a,b,c,x[10], 9, 0x2441453ul); GG(c,d,a,b,x[15],14,0xd8a1e681ul); GG(b,c,d,a,x[ 4],20,0xe7d3fbc8ul);
        GG(a,b,c,d,x[ 9], 5,0x21e1cde6ul); GG(d,a,b,c,x[14], 9,0xc33707d6ul); GG(c,d,a,b,x[ 3],14,0xf4d50d87ul); GG(b,c,d,a,x[ 8],20,0x455a14edul);
        GG(a,b,c,d,x[13], 5,0xa9e3e905ul); GG(d,a,b,c,x[ 2], 9,0xfcefa3f8ul); GG(c,d,a,b,x[ 7],14,0x676f02d9ul); GG(b,c,d,a,x[12],20,0x8d2a4c8aul);
        HH(a,b,c,d,x[ 5], 4,0xfffa3942ul); HH(d,a,b,c,x[ 8],11,0x8771f681ul); HH(c,d,a,b,x[11],16,0x6d9d6122ul); HH(b,c,d,a,x[14],23,0xfde5380cul);
        HH(a,b,c,d,x[ 1], 4,0xa4beea44ul); HH(d,a,b,c,x[ 4],11,0x4bdecfa9ul); HH(c,d,a,b,x[ 7],16,0xf6bb4b60ul); HH(b,c,d,a,x[10],23,0xbebfbc70ul);
        HH(a,b,c,d,x[13], 4,0x289b7ec6ul); HH(d,a,b,c,x[ 0],11,0xeaa127faul); HH(c,d,a,b,x[ 3],16,0xd4ef3085ul); HH(b,c,d,a,x[ 6],23,0x04881d05ul);
        HH(a,b,c,d,x[ 9], 4,0xd9d4d039ul); HH(d,a,b,c,x[12],11,0xe6db99e5ul); HH(c,d,a,b,x[15],16,0x1fa27cf8ul); HH(b,c,d,a,x[ 2],23,0xc4ac5665ul);
        II(a,b,c,d,x[ 0], 6,0xf4292244ul); II(d,a,b,c,x[ 7],10,0x432aff97ul); II(c,d,a,b,x[14],15,0xab9423a7ul); II(b,c,d,a,x[ 5],21,0xfc93a039ul);
        II(a,b,c,d,x[12], 6,0x655b59c3ul); II(d,a,b,c,x[ 3],10,0x8f0ccc92ul); II(c,d,a,b,x[10],15,0xffeff47dul); II(b,c,d,a,x[ 1],21,0x85845dd1ul);
        II(a,b,c,d,x[ 8], 6,0x6fa87e4ful); II(d,a,b,c,x[15],10,0xfe2ce6e0ul); II(c,d,a,b,x[ 6],15,0xa3014314ul); II(b,c,d,a,x[13],21,0x4e0811a1ul);
        II(a,b,c,d,x[ 4], 6,0xf7537e82ul); II(d,a,b,c,x[11],10,0xbd3af235ul); II(c,d,a,b,x[ 2],15,0x2ad7d2bbul); II(b,c,d,a,x[ 9],21,0xeb86d391ul);
        state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
        #undef F #undef G #undef H #undef I #undef FF #undef GG #undef HH #undef II #undef ROTATE_LEFT
    }
    inline void encode(const uint32_t* input, unsigned char* output, size_t length) {
        for (size_t i = 0, j = 0; j < length; i++, j += 4) {
            output[j] = (unsigned char)(input[i] & 0xff);
            output[j+1] = (unsigned char)((input[i] >> 8) & 0xff);
            output[j+2] = (unsigned char)((input[i] >> 16) & 0xff);
            output[j+3] = (unsigned char)((input[i] >> 24) & 0xff);
        }
    }
    inline void decode(const unsigned char* input, uint32_t* output, size_t length) {
        for (size_t i = 0, j = 0; j < length; i++, j += 4)
            output[i] = ((uint32_t)input[j]) | (((uint32_t)input[j+1]) << 8)
                | (((uint32_t)input[j+2]) << 16) | (((uint32_t)input[j+3]) << 24);
    }

    uint32_t state[4], count[2];
    unsigned char buffer[64];
    bool finalized = false;
};
