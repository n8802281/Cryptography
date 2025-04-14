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

tuple<Integer, Integer, Integer> extended_gcd(Integer a, Integer b){
    if (a == 0)
        return make_tuple(b, 0, 1);
    Integer gcd, x, y;
    tie(gcd, x, y) = extended_gcd(b % a, a);
    return make_tuple(gcd, (y - (b / a) * x), x);
}

int main() {
    ofstream outfile("out.txt");
    //E1 example
    /*
    Integer e1("0x11");
    Integer n1("0xb14022eef719f1bb");
    string plain1 = "Alice";
    RSA::PublicKey pubKey1;
    pubKey1.Initialize(n1, e1);
    Integer m1((const byte*)plain1.data(), plain1.size());
    Integer c1 = pubKey1.ApplyFunction(m1);
    //cout << hex << c1 << endl;
    outfile << hex << c1 << endl;
    */

    //E2
    Integer e2("0x11");
    Integer n2("0xb2c8d1404ed5fc2f7ad1254bb428f0d5");
    string plain2 = "Hello World!";
    RSA::PublicKey pubKey2;
    pubKey2.Initialize(n2, e2);
    Integer m2((const byte*)plain2.data(), plain2.size());
    Integer c2 = pubKey2.ApplyFunction(m2);
    //cout << hex << c2 << endl;
    outfile << hex << c2 << endl;

    //E3
    Integer e3("0x10001");
    Integer n3("0xcf625a8e47bc1cf9a3b517b31d870108c0cd97466003842a3b394d6cd857e9b7");
    string plain3 = "RSA is public key.";
    RSA::PublicKey pubKey3;
    pubKey3.Initialize(n3, e3);
    Integer m3((const byte*)plain3.data(), plain3.size());
    Integer c3 = pubKey3.ApplyFunction(m3);
    //cout << hex << c3 << endl;
    outfile << hex << c3 << endl;

    //D1 example
    /*
    Integer n4("0x9d001e6473dfacf9");
    Integer d4("0x16282b21a7866bf5");
    // cout << dec << n4 << endl; n4 = 11313075680744287481 = 3351720919 * 3375303599
    string plain4 = "154c638cd3615216";
    RSA::PublicKey pubKey4;
    pubKey4.Initialize(n4, d4);
    string cipher4;
    for (int i = 0; i < plain4.size(); i += 2){
        int tmp1, tmp2;
        if ('a' <= plain4[i] && plain4[i] <= 'z')
            tmp1 = plain4[i] - 'a' + 10;
        else if ('A' <= plain4[i] && plain4[i] <= 'Z')
            tmp1 = plain4[i] - 'A' + 10;
        else
            tmp1 = plain4[i] - '0';

        if ('a' <= plain4[i + 1] && plain4[i + 1] <= 'z')
            tmp2 = plain4[i + 1] - 'a' + 10;
        else if ('A' <= plain4[i + 1] && plain4[i + 1] <= 'Z')
            tmp2 = plain4[i + 1] - 'A' + 10;
        else
            tmp2 = plain4[i + 1] - '0';
        tmp1 = tmp1 * 16 + tmp2;
        cipher4 += (char)tmp1;
    }
    Integer c4((const byte*)cipher4.data(), cipher4.size());
    Integer m4 = pubKey4.ApplyFunction(c4);

    string result4, str4;
    stringstream ss4;
    ss4 << hex << m4;
    ss4 >> str4;
    for (int i = 0; i < str4.size() - 1; i += 2) {
        int tmp1, tmp2;
        if ('a' <= str4[i] && str4[i] <= 'z')
            tmp1 = str4[i] - 'a' + 10;
        else if ('A' <= str4[i] && str4[i] <= 'Z')
            tmp1 = str4[i] - 'A' + 10;
        else
            tmp1 = str4[i] - '0';

        if ('a' <= str4[i + 1] && str4[i + 1] <= 'z')
            tmp2 = str4[i + 1] - 'a' + 10;
        else if ('A' <= str4[i + 1] && str4[i + 1] <= 'Z')
            tmp2 = str4[i + 1] - 'A' + 10;
        else
            tmp2 = str4[i + 1] - '0';
        tmp1 = tmp1 * 16 + tmp2;
        result4 += (char)tmp1;
    }
    //cout << result4 << endl;
    outfile << result4 << endl;
    */
    //D2
    Integer n5("0xd6361e40b2d619970ead338912a273adb75a4ce21356304834753fe94e6de24b");
    Integer d5("0x12e6a85100b889c9905a939b274a91bc57ca85d52e6c464fb455c86a29d63c89");
    //cout << dec << d5 << endl;
    //cout << dec << n5 << endl;
    //d5 = 8549167776615678865827938727496097698529954274446691066501057712531764034697
    //n5 = 96890568134977693812716638911622440583962074735097356490270011720901740847691
    string plain5 = "a1676afd68a2fc67dac32c633600b76fa90aca9f9cca5201490a20c8b01a061a";
    RSA::PublicKey pubKey5;
    pubKey5.Initialize(n5, d5);
    string cipher5;
    for (int i = 0; i < plain5.size(); i += 2) {
        int tmp1, tmp2;
        if ('a' <= plain5[i] && plain5[i] <= 'z')
            tmp1 = plain5[i] - 'a' + 10;
        else if ('A' <= plain5[i] && plain5[i] <= 'Z')
            tmp1 = plain5[i] - 'A' + 10;
        else
            tmp1 = plain5[i] - '0';

        if ('a' <= plain5[i + 1] && plain5[i + 1] <= 'z')
            tmp2 = plain5[i + 1] - 'a' + 10;
        else if ('A' <= plain5[i + 1] && plain5[i + 1] <= 'Z')
            tmp2 = plain5[i + 1] - 'A' + 10;
        else
            tmp2 = plain5[i + 1] - '0';
        tmp1 = tmp1 * 16 + tmp2;
        cipher5 += (char)tmp1;
    }
    Integer c5((const byte*)cipher5.data(), cipher5.size());
    Integer m5 = pubKey5.ApplyFunction(c5);
    string result5, str5;
    stringstream ss5;
    ss5 << hex << m5;
    ss5 >> str5;
    for (int i = 0; i < str5.size() - 1; i += 2) {
        int tmp1, tmp2;
        if ('a' <= str5[i] && str5[i] <= 'z')
            tmp1 = str5[i] - 'a' + 10;
        else if ('A' <= str5[i] && str5[i] <= 'Z')
            tmp1 = str5[i] - 'A' + 10;
        else
            tmp1 = str5[i] - '0';

        if ('a' <= str5[i + 1] && str5[i + 1] <= 'z')
            tmp2 = str5[i + 1] - 'a' + 10;
        else if ('A' <= str5[i + 1] && str5[i + 1] <= 'Z')
            tmp2 = str5[i + 1] - 'A' + 10;
        else
            tmp2 = str5[i + 1] - '0';
        tmp1 = tmp1 * 16 + tmp2;
        result5 += (char)tmp1;
    }
    //cout << result5 << endl;
    outfile << result5 << endl;

    //Find public key
    //d5 = 8549167776615678865827938727496097698529954274446691066501057712531764034697
    //n5 = 96890568134977693812716638911622440583962074735097356490270011720901740847691
    //   = 307432580251824643205317489590060797683 (39 digits) × 315160377783033093386040155951687656777 (39 digits);
    //by https://www.alpertron.com.ar/ECM.HTM
    //(p-1)(q-1) = 307432580251824643205317489590060797682 * 315160377783033093386040155951687656776 
    //           = 96890568134977693812716638911622440583339481777062498753678654075359992393232
    //e = d^(-1) mod (p-1)(q-1)
    //use Extended Euclidean Algorithm to find e
    Integer A("96890568134977693812716638911622440583339481777062498753678654075359992393232");
    Integer B("8549167776615678865827938727496097698529954274446691066501057712531764034697");
    tuple<Integer, Integer, Integer> t = extended_gcd(A, B);
    Integer gcd = get<0>(t);
    Integer C = get<2>(t);
    C += A;
    //cout << C << endl << (C * B) % A << endl;
    outfile << hex << C << endl;

    //check the ans
    /*
    Integer e6 = C;
    Integer n6 = n5;
    string plain6 = "ECC has shorter keys.";
    RSA::PublicKey pubKey6;
    pubKey6.Initialize(n6, e6);
    Integer m6((const byte*)plain6.data(), plain6.size());
    Integer c6 = pubKey6.ApplyFunction(m6);
    cout << hex << c6 << endl;
    //outfile << hex << c2 << endl;
    */
    return 0;
}
