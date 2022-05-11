//! duckdice verifier
//! barrystyle 13052022

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>

#include <openssl/sha.h>

void get_roll_hash(std::string& server_seed, std::string& client_seed, std::string& nonce, int& result)
{
    char buffer[128];
    memset(buffer, 0, sizeof(buffer));
    int buflen = server_seed.size() + client_seed.size() + nonce.size();
    sprintf(buffer, "%s%s%s", server_seed.c_str(), client_seed.c_str(), nonce.c_str());

    char hash[64];
    memset(hash, 0, sizeof(hash));
    SHA512((const unsigned char*)buffer, buflen, (unsigned char*)hash);

    char hashhex[128];
    memset(hashhex, 0, sizeof(hashhex));
    for (int i = 0; i < 64; i++) {
        sprintf(hashhex + (i * 2), "%02hhx", hash[i]);
    }

    int index = 0;
    char hexslice[6];
    memset(hexslice, 0, sizeof(hexslice));
    unsigned int lucky;
    do {
        memcpy(hexslice, hashhex + index, 5);
        std::string s = std::string(hexslice);
        lucky = std::stoll(s, nullptr, 16);
        index += 5;
    } while (lucky >= 1000000);

    result = lucky % 10000;
}

int main()
{
    int result;
    std::string nonce;
    std::string ss = "99b6da6d09ac4db1482089f575357931a42539743deefae0d52bd0390932d481";
    std::string cs = "WIUwM9xvDqhSyfAU0PUo9W8Yx8Rj8V";

    int nonceint = 0;
    while (++nonceint < 10000) {
        nonce = std::to_string(nonceint);
        get_roll_hash(ss, cs, nonce, result);
        printf("%d,%d\n", nonceint, result);
    }

    return 0;
}
