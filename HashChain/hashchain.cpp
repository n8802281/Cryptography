#include <iostream>
#include <stdlib.h>
#include <randpool.h>
#include <osrng.h>
#include <rsa.h>
#include <hex.h>
#include <files.h>
#include <iostream>
#include <stdlib.h>
#include <integer.h>
#include <filters.h>
#include <randpool.h>
#include <tuple>
#include <fstream>
using namespace std;
using namespace CryptoPP;

int main() {
    ofstream outfile("out.txt");

    //part 1
    // p1
    SHA256 hash0;
    string message0 = "Hello!";
    string answer0;
    StringSource s0(message0, true, new HashFilter(hash0, new HexEncoder(new StringSink(answer0))));
    //cout << answer0 << endl;
    //outfile << answer0 << endl;

    // p2
    SHA256 hash1;
    string message1 = "Bitcoin is a cryptocurrency, a form of electronic cash.";
    string answer1;
    StringSource s1(message1, true, new HashFilter(hash1, new HexEncoder(new StringSink(answer1))));
    //cout << answer1 << endl;
    outfile << answer1 << endl;

    //part 2
    SHA256 hash2;
    int searchfrom = 0;
    // 0
    string initial0 = "B4056DF6691F8DC72E56302DDAD345D65FEAD3EAD9299609A826E2344EB63AA4";
    outfile << searchfrom << endl
            << initial0 << endl
            << "00000000" << endl
            << "2767667C2AF3BE01EFAC4FB387EC27C10B9D3BEE9C5D48CFF4CFB9F523560B24" << endl;
    searchfrom++;
    // 1
    string initial1 = "2767667C2AF3BE01EFAC4FB387EC27C10B9D3BEE9C5D48CFF4CFB9F523560B24";
    outfile << searchfrom << endl
            << initial1 << endl
            << "0000000A" << endl
            << "0DE32E85C2AC9D96659D42C8A3EA3D2C05FDE384B468E6EFE062B6E21288CBCA" << endl;
    searchfrom++;
    // 2
    string initial2 = "0DE32E85C2AC9D96659D42C8A3EA3D2C05FDE384B468E6EFE062B6E21288CBCA";
    outfile << searchfrom << endl
            << initial2 << endl
            << "000001E3" << endl
            << "00EE1063B3EB05C11A21D0F6302ABC473FEF1F97686DA8F44C73C9575FD842B7" << endl;
    searchfrom++;
    // 3
    string initial3 = "00EE1063B3EB05C11A21D0F6302ABC473FEF1F97686DA8F44C73C9575FD842B7";
    outfile << searchfrom << endl
            << initial3 << endl
            << "00000BE6" << endl
            << "000BDC7682D6E663CA8C1F6C8491C3B59A460187F8E67A60DDC94AA0D8E711B0" << endl;
    searchfrom++;
    // 4
    string initial4 = "000BDC7682D6E663CA8C1F6C8491C3B59A460187F8E67A60DDC94AA0D8E711B0";
    outfile << searchfrom << endl
            << initial4 << endl
            << "00075281" << endl
            << "00007EF015AAD51F77336EF9EB2479BEC15A061EC182417631F1A61AF95734A5" << endl;
    searchfrom++;
    // 5
    string initial5 = "00007EF015AAD51F77336EF9EB2479BEC15A061EC182417631F1A61AF95734A5";
    outfile << searchfrom << endl
            << initial5 << endl
            << "00018719" << endl
            << "000007DEA2E67A5423523F4403B39770ACCB398295CE2188D5D064FD989967F5" << endl;
    searchfrom++;
    // 6
    string initial6 = "000007DEA2E67A5423523F4403B39770ACCB398295CE2188D5D064FD989967F5";
    outfile << searchfrom << endl
            << initial6 << endl
            << "00CA6250" << endl
            << "000000B1010437E82D8E7D6550D87497E0503A53358B012EDA32C000D47B348B" << endl;
    searchfrom++;
    // 7
    string initial7 = "000000B1010437E82D8E7D6550D87497E0503A53358B012EDA32C000D47B348B";
    outfile << searchfrom << endl
            << initial7 << endl
            << "1DF97256" << endl
            << "0000000FE3BEE5E2532C749995C88B2DE15A33035C8D08209CCD6C4F27DD688B" << endl;
    searchfrom++;
    // 8
    string initial8 = "0000000FE3BEE5E2532C749995C88B2DE15A33035C8D08209CCD6C4F27DD688B";
    outfile << searchfrom << endl
            << initial8 << endl
            << "6EF9E36C" << endl
            << "00000000C6775A318F60CDA2F47D51A3749E51D1B04E455371F03A5F599C0FD7" << endl;
    searchfrom++;
    // 9
    string initial9 = "00000000C6775A318F60CDA2F47D51A3749E51D1B04E455371F03A5F599C0FD7";

    string preview = initial9;
    string encoded;
    string message2;
    string current;
    int endup = 0;
    srand((long long)time(NULL));
    for(int leading_zeroes = searchfrom; leading_zeroes <= 64; leading_zeroes++){
        while(1){
            // nonce
            long long cur_nonce = rand() % (1LL << 28) + (1LL << 28) * 4;
            char ch;
            string nonce;
            for(int i = 0; i < 8; i++){
                int cur = cur_nonce & 15;
                cur_nonce >>= 4;
                if (cur >= 10){
                    ch = 'A' + cur - 10;
                }else 
                    ch = '0' + cur - 10;
                nonce = ch + nonce;
            }

            // encoded hex string
            encoded = preview + nonce;

            // hex decoder
            HexDecoder decoder;
            decoder.Put((byte*)encoded.data(), encoded.size());
            decoder.MessageEnd();
            word64 size = decoder.MaxRetrievable();
            message2.resize(size);
            decoder.Get((byte*)&message2[0], message2.size());

            // sha256
            current.clear();
            StringSource s(message2, true, new HashFilter(hash2, new HexEncoder(new StringSink(current))));

            // verify
            int legal = 1;
            for(int i = 0; i < leading_zeroes; i++)
                if(current[i] != '0')
                    legal = 0;
            if(current[leading_zeroes] == '0')
                legal = 0;

            if(legal){
                outfile << leading_zeroes << endl
                        << preview << endl
                        << nonce << endl
                        << current << endl;
                //cout << leading_zeroes << endl;
                break;
            }

        }
        // change for next round
        preview = current;
    }
}