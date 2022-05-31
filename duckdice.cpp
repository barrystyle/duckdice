//! duckdice verifier
//! barrystyle 13052022

#include <stdio.h>
#include <string.h>

#include <fstream>

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
    int tokid, betid;
    const char s[2] = ",";
    const char t[2] = "=";
    std::string line, data, fields[16];
    std::ifstream file("bets.csv");

    // read in the delimited data
    while(std::getline(file, line))
    {
        tokid = 0;
        bool bettype, betresult;
	int nonce, result, threshold;

        char convert[768];
        memset(convert, 0, sizeof(convert));
        sprintf(convert, "%s", line.c_str());

        char *token = strtok(convert, s);
        while (token != NULL) {
            fields[tokid++] = std::string(token);
            token = strtok(NULL, s);
        }

        nonce = std::atoi(fields[4].c_str());
        betresult = fields[5] == "Win";
        bettype = fields[6] == "High";
        result = std::atoi(fields[7].c_str());
        threshold = std::atoi(fields[8].c_str());

        if (fields[15].size() > 32)
        {
            char betverify[768];
            memset(betverify, 0, sizeof(betverify));
            sprintf(betverify, "%s", fields[15].c_str());

            betid = 0;
            int vernonce;
            char hash[64+1];
            char client[64+1];

            token = strtok(betverify, t);
            while (token != NULL)
            {
                //! server seed
                if (betid == 1) {
                    sprintf(hash, "%s", token);
                    memset(hash+64, 0, 1);
                }

                //! client seed (this is unsafe)
                if (betid == 2) {
                    sprintf(client, "%s", token);
                    for (unsigned int i=0; i<64; i++) {
                        if (client[i] == '&') {
                            memset(client+i, 0, 1);
                            break;
                        }
                    }
                }

                //! nonce
                if (betid == 3) {
                    vernonce = std::atoi(token);
                }

                betid++;
                token = strtok(NULL, t);
            }

            // lets verify
            if (nonce != vernonce) {
                printf("nonce differs\n");
                return 0;
            }

            int realresult;
            std::string a = std::string(hash);
            std::string b = std::string(client);
            std::string c = std::to_string(nonce);
            get_roll_hash(a, b, c, realresult);

            printf("%s %s.. %6d %4d %4d %s %s ", hash,
                                         std::string(client).substr(0,12).c_str(),
                                         nonce,
                                         result,
                                         threshold,
                                         bettype ? "high" : "low ",
                                         betresult ? "win " : "lose");

            if (result != realresult) {
                printf("result differs (%d vs %d)\n", result, realresult);
            } else {
                bool valid = true;
                if (!bettype) {              // low
                    if (result < threshold)
                        if (!betresult)
                            valid = false;
                } else {                     // high
                    if (result > threshold)
                        if (!betresult)
                            valid = false;
                }

                if (valid)
                    printf("authentic\n");
                else
                    printf("fraudulent\n");
            }
        }
    }

    return 0;
}
