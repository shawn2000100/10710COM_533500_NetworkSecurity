#include <iostream>
#include <cstdio>
#include <string>
#include <bitset>
#include <iomanip>

using namespace std;
typedef unsigned char uint8_t;
typedef unsigned short int uint16_t;
typedef bitset<8> byte;
typedef bitset<32> word;

const int Nr = 10;                       // AES-128 needs 10 round of encryption
const int Nk = 4;                        // the 128bits key equal to 4 words
uint8_t s_box_ary[16][16] = {0};         // S-BOX BJ4, the most difficult part of this Homework!!!!!
uint8_t inv_s_box_ary[16][16] = {0};     // Inv-S-BOX, one of the nightmare.......
word Rcon[10] = {0x01000000, 0x02000000, // This is just the round constant for the KeyExpansion step
                 0x04000000, 0x08000000,
                 0x10000000, 0x20000000,
                 0x40000000, 0x80000000,
                 0x1b000000, 0x36000000};

/************************* These fuctions are for the s-box generation ***********************/
uint16_t polynomialMutil(uint8_t a, uint8_t b);                       // The multiplication of GF(2^8)
uint8_t findHigherBit(uint16_t val);                                  // Find the leftest bit, called by GF_division
uint8_t gf28_div(uint16_t div_ed, uint16_t div, uint16_t *remainder); // The division of the GF(2^8)
uint8_t extEuclidPolynomial(uint8_t a, uint16_t m);                   // Extended Euclid Algorithm. To find the multiplication inverse in GF(2^8)
uint8_t uint8_tTransformation(uint8_t a, uint8_t x);                  // 找到GF上的乘法反元素後，我們再套用一個事先定義好的數學公式來計算S-BOX的最終值
uint8_t invuint8_tTransformation(uint8_t a, uint8_t x);               // Inv-S-BOX變換所需要用到的數學運算
void s_box_gen(void);                                                 // S-BOX BJ4, the most difficult part of this Homework!!!!!
void inv_s_box_gen(void);                                             // Inv-S-BOX, one of the nightmare.......

/************************* Below are for the AES encipher & decipher ************************************************/
void encrypt(byte in[4 * 4], word w[4 * (Nr + 1)]);// AES-Encryption
void AddRoundKey(byte mtx[16], word k[4]);         // Just XOR each bytes with Expanded key "w"
void SubBytes(byte mtx[4 * 4]);                    // SubByte is just simply look-up the S-BOX table
void ShiftRows(byte mtx[4 * 4]);                   // Simply do the left row shift
byte GFMul(byte a, byte b);                        // The multiplication of Galois Field, called by the MixColumns function
void MixColumns(byte mtx[4 * 4]);                  // This function use a constant matrix and GFMul

void decrypt(byte in[4 * 4], word w[4 * (Nr + 1)]);// AES-Decryption BJ4
void InvSubBytes(byte mtx[4 * 4]);                 // For the decipher step, this is just the inverse calculation of SubBytes
void InvShiftRows(byte mtx[4 * 4]);                // The inverse function of left row shift
void InvMixColumns(byte mtx[4 * 4]);               // The inverse function of MixColumns

/************************* some necessary functions for the implementation of AES ***********************************/
void KeyExpansion(byte key[4 * Nk], word w[4 * (Nr + 1)]); // We will use 11 different variation of the original Key
word RotWord(word rw);                                     // This is the sub-function of AES, simply left rotate the word
word SubWord(word sw);                                     // This is the sub-function of AES, simply look-up the S-BOX (SubByte)
void input_func(uint8_t *input);                           // To collect the input
word Word(byte &k1, byte &k2, byte &k3, byte &k4);         // To make 4 bytes into a word(32bits)

/////////////////////////////////////////////
//      ___  ___       ___   _   __   _    //
//     /   |/   |     /   | | | |  \ | |   //
//    / /|   /| |    / /| | | | |   \| |   //
//   / / |__/ | |   / / | | | | | |\   |   //
//  / /       | |  / /  | | | | | | \  |   //
// /_/        |_| /_/   |_| |_| |_|  \_|   //
//                                         //
/////////////////////////////////////////////
/* This is main function */
int main() {
    /* Here we use a lot of sub-functions to generate both the S-BOX and Inv-S-BOX for future use */
    s_box_gen();
    inv_s_box_gen();


    /* Input function */
    uint8_t tmp_plain[16] = {0};
    uint8_t tmp_key[16] = {0};
    input_func(tmp_plain);
    input_func(tmp_key);

    // convert Plaintext from uint8_t to byte bitset(8bits)
    byte plain[16] = {0};
    for (int i = 0; i < 16; ++i) {
        plain[i] = tmp_plain[i];
    }
    // convert Key from uint8_t to byte bitset(8bits)
    byte key[16];
    for (int i = 0; i < 16; ++i) {
        key[i] = tmp_key[i];
    }
    // After collect the input, we have to transpose this matrix because the data is stored from top to down
    // 注意: 大坑，AES加密的資料是由上往下儲存的，我一開始搞錯，從左到右儲存，結果Debug搞了超久
    byte test_tmp[16] = {0};
    for(int i = 0; i < 16; ++i){
        test_tmp[i] = plain[i];
    }
    for(int i = 0; i < 4; ++i){
        for(int j = 0; j < 4; ++j){
            plain[4*i + j] = test_tmp[i + 4*j];
        }
    }
//    // 現在我們初步的處理好輸入資料了，現在來測試plaintext 和 key 是否接收正確無誤
//    cout << "PLAIN IS: ";
//    for (int i = 0; i < 16; ++i)
//        cout << setw(2) << setfill('0') << hex << plain[i].to_ulong() << " ";
//    cout << endl;
//    cout << "KEY IS  : ";
//    for (int i = 0; i < 16; ++i)
//        cout << setw(2) << setfill('0') << hex << key[i].to_ulong() << " ";
//    cout << endl;


    /* we expand the original Key to 44 words(176bytes) */
    word w[44] = {0};
    KeyExpansion(key, w);
//    // 测试KeyExpand
//    for (int i = 0; i < 44; ++i)
//        cout << "w[" << dec << i << "] = " << setw(8) << setfill('0') << hex << w[i].to_ulong() << endl;
//    cout << endl;


    /* After Key expansion, we now start to encrypt */
    cout << "--------Encryption--------" << endl;
    encrypt(plain, w);
    cout << "Ciphertext: ";
    for (int i = 0; i < 4; ++i) {
        for(int j = 0; j < 4; ++j) {
            cout << setw(2) << setfill('0') << hex << plain[i + 4*j].to_ulong() << " ";
        }
    }
    cout << endl << endl;


    /* After Encryption, we now start to Decrypt */
    cout << "--------Decryption--------" << endl;
    decrypt(plain, w);
    cout << "Plaintext: ";
    for (int i = 0; i < 4; ++i) {
        for(int j = 0; j < 4; ++j) {
            cout << setw(2) << setfill('0') << hex << plain[i + 4*j].to_ulong() << " ";
        }
    }
    cout << endl;

    return 0;
}




/****************************************************************************************
 ********************* Source Code Implementation **************************************
 *
 *
 *
 ***************************************************************************************
*****************************************************************************************/
/* The multiplication of GF(2^8) */
uint16_t polynomialMutil(uint8_t a, uint8_t b) {
    uint16_t tmp[8] = {0};
    // 我們把input a 依序與input b做乘法，(b >> i) & 0x1 就是每次都將多項式 a 與多項式 b 的係數依序從右至左相乘
    for (uint8_t i = 0; i < 8; i++) {
        tmp[i] = (a << i) * ((b >> i) & 0x1);
    }

    // 依序做好乘法後的結果會存到tmp[0] ~ tmp[8], 我們直接把所有結果加總, 存入tmp[0]即可 (也可以再多宣告一個變數來存加總結果，一樣意思)
    tmp[0] = tmp[0] ^ tmp[1] ^ tmp[2] ^ tmp[3] ^ tmp[4] ^ tmp[5] ^ tmp[6] ^ tmp[7];
    return tmp[0];
}

/* Find the leftest bit, called by GF_division */
uint8_t findHigherBit(uint16_t val) {
    int i = 0;
    while (val) {
        ++i;
        val = val >> 1;
    }
    return i;
}

/* The division of the GF(2^8) */
uint8_t gf28_div(uint16_t div_ed, uint16_t div, uint16_t *remainder) {
    // 暫存被除式
    uint16_t r0 = div_ed;
    // 暫存商(quotient)
    uint8_t qn = 0;
    // 被除數與除數間差了幾個bits
    int bitCnt = findHigherBit(r0) - findHigherBit(div);

    // 除法的過程，有點難解釋
    while (bitCnt >= 0) {
        qn = qn | (1 << bitCnt);
        r0 = r0 ^ (div << bitCnt);
        bitCnt = findHigherBit(r0) - findHigherBit(div);
    }

    *remainder = r0; // 順便改變餘數 (記得這裡要用pass-by-address方式來傳遞參數)
    return qn;       // 回傳商數
}

/* Extended Euclid Algorithm. To find the multiplication inverse in GF(2^8) */
uint8_t extEuclidPolynomial(uint8_t a, uint16_t m) {
    // 基本上這個演算法還滿複雜的，我是直接參考Wiki上的Pseudo Code來實作
    uint16_t r0, r1, r2;
    uint8_t qn, v0, v1, v2, w0, w1, w2;
    r0 = m;
    r1 = a;
    v0 = 1;
    v1 = 0;
    w0 = 0;
    w1 = 1;
    while (r1 != 1) {
        qn = gf28_div(r0, r1, &r2);
        v2 = v0 ^ polynomialMutil(qn, v1);
        w2 = w0 ^ polynomialMutil(qn, w1);
        r0 = r1;
        r1 = r2;
        v0 = v1;
        v1 = v2;
        w0 = w1;
        w1 = w2;
    }
    return w1; // 它就是GF(2^8)上的乘法反元素
}

/* 找到GF上的乘法反元素後，我們再套用一個事先定義好的數學公式來計算S-BOX的最終值 */
uint8_t uint8_tTransformation(uint8_t a, uint8_t x) {
    // 基本上這個公式的數學原理滿複雜的，這裡直接套公式進行運算即可
    uint8_t tmp[8] = {0};
    for (uint8_t i = 0; i < 8; i++) {
        tmp[i] = (((a >> i) & 0x1) ^ ((a >> ((i + 4) % 8)) & 0x1) ^ ((a >> ((i + 5) % 8)) & 0x1) ^
                  ((a >> ((i + 6) % 8)) & 0x1) ^ ((a >> ((i + 7) % 8)) & 0x1) ^ ((x >> i) & 0x1)) << i;
    }
    tmp[0] = tmp[0] + tmp[1] + tmp[2] + tmp[3] + tmp[4] + tmp[5] + tmp[6] + tmp[7];
    return tmp[0];
}

/* Inv-S-BOX變換所需要用到的數學運算 */
uint8_t invuint8_tTransformation(uint8_t a, uint8_t x) {
    // 基本上這個公式的數學原理滿複雜的，這裡直接套公式進行運算即可
    uint8_t tmp[8] = {0};
    for (uint8_t i = 0; i < 8; i++) {
        tmp[i] = (((a >> ((i + 2) % 8)) & 0x1) ^ ((a >> ((i + 5) % 8)) & 0x1) ^ ((a >> ((i + 7) % 8)) & 0x1) ^
                  ((x >> i) & 0x1)) << i;
    }
    tmp[0] = tmp[0] + tmp[1] + tmp[2] + tmp[3] + tmp[4] + tmp[5] + tmp[6] + tmp[7];
    return tmp[0];
}

/* To generate the S-BOX */
void s_box_gen(void) {
    // 第一步，按照0x00, 0x01..., 0xFF的順序初始化S-BOX
    for (uint8_t i = 0; i < 0x10; i++) {
        for (uint8_t j = 0; j < 0x10; j++) {
            s_box_ary[i][j] = ((i << 4) & 0xF0) + (j & (0xF));
        }
    }

    // 第二步，求S-BOX在GF(2^8)上的乘法逆元素，規定0映射到自身
    for (uint8_t i = 0; i < 0x10; i++) {
        for (uint8_t j = 0; j < 0x10; j++) {
            if (s_box_ary[i][j] != 0) {
                s_box_ary[i][j] = extEuclidPolynomial(s_box_ary[i][j], 0x11B);
            }
        }
    }

    // 第三步，依照S-BOX的公式對每個Bytes做轉換
    for (uint8_t i = 0; i < 0x10; i++) {
        for (uint8_t j = 0; j < 0x10; j++) {
            s_box_ary[i][j] = uint8_tTransformation(s_box_ary[i][j], 0x63);
        }
    }

}

/* To generate the Inv-S-BOX */
void inv_s_box_gen(void) {
    // 第一步，按照0x00, 0x01..., 0xFF的順序初始化S-BOX
    for (uint8_t i = 0; i < 0x10; i++) {
        for (uint8_t j = 0; j < 0x10; j++) {
            inv_s_box_ary[i][j] = ((i << 4) & 0xF0) + (j & (0xF));
        }
    }

    // 第二步，對每個Byte做轉換，這邊直接套用課本定義好的公式即可
    for (uint8_t i = 0; i < 0x10; i++) {
        for (uint8_t j = 0; j < 0x10; j++) {
            inv_s_box_ary[i][j] = invuint8_tTransformation(inv_s_box_ary[i][j], 0x05);
        }
    }

    // 第三步，求其在GF(2^8)上的乘法逆元素，規定0映射到自身
    for (uint8_t i = 0; i < 0x10; i++) {
        for (uint8_t j = 0; j < 0x10; j++) {
            if (inv_s_box_ary[i][j] != 0) {
                inv_s_box_ary[i][j] = extEuclidPolynomial(inv_s_box_ary[i][j], 0x11B);
            }
        }
    }

}

/* 基本上就是接收input的函數不解釋 */
void input_func(uint8_t *input) {
    // collect input(hex)
    uint8_t temp[49] = {0};
    for (int c = 0; c < 48; c++) {
        temp[c] = getchar();
    }
    // transform to decimal
    for (int c = 0; c < 48; c++) {
        if (temp[c] >= '0' && temp[c] <= '9') {
            temp[c] = temp[c] - '0';
        } else if (temp[c] >= 'a' && temp[c] <= 'f') {
            temp[c] = temp[c] - 'a' + 10;
        } else if (temp[c] >= 'A' && temp[c] <= 'F') {
            temp[c] = temp[c] - 'A' + 10;
        }
    }
    // transform to uint8_t
    for (int i = 0; i < 16; ++i) {
        input[i] = 16 * temp[3 * i] + temp[3 * i + 1];
    }

}

/* AES的其中一個步驟，簡單來說就是對S-BOX查表做轉換 */
void SubBytes(byte mtx[4 * 4]) {
//    cout << "+++++ 開始 SubBytes +++++" << endl;
//    for (int i = 0; i < 16; ++i) {
//        cout << setw(2) << setfill('0') << hex << mtx[i].to_ulong() << " ";
//        if ((i + 1) % 4 == 0)
//            cout << endl;
//    }

    for (int i = 0; i < 16; ++i) {
        int row = mtx[i][7] * 8 + mtx[i][6] * 4 + mtx[i][5] * 2 + mtx[i][4];
        int col = mtx[i][3] * 8 + mtx[i][2] * 4 + mtx[i][1] * 2 + mtx[i][0];
        mtx[i] = s_box_ary[row][col];
    }

//    cout << "----- 結束SubBytes -----" << endl;
//    for (int i = 0; i < 16; ++i) {
//        cout << setw(2) << setfill('0') << hex << mtx[i].to_ulong() << " ";
//        if ((i + 1) % 4 == 0)
//            cout << endl;
//    }
//    cout << endl;
}

/* Row shift, 第[i]row就往左shift i 格 (i = 0 to 3) */
void ShiftRows(byte mtx[4 * 4]) {
//    cout << "+++++ 開始 ShiftRows +++++" << endl;
//    for (int i = 0; i < 16; ++i) {
//        cout << setw(2) << setfill('0') << hex << mtx[i].to_ulong() << " ";
//        if ((i + 1) % 4 == 0)
//            cout << endl;
//    }

    // 第二列左移一位
    byte temp = mtx[4];
    for (int i = 0; i < 3; ++i)
        mtx[i + 4] = mtx[i + 5];
    mtx[7] = temp;
    // 第三列左移二位
    for (int i = 0; i < 2; ++i) {
        temp = mtx[i + 8];
        mtx[i + 8] = mtx[i + 10];
        mtx[i + 10] = temp;
    }
    // 第四列左移三位
    temp = mtx[15];
    for (int i = 3; i > 0; --i)
        mtx[i + 12] = mtx[i + 11];
    mtx[12] = temp;

//    cout << "----- 結束 ShiftRows -----" << endl;
//    for (int i = 0; i < 16; ++i) {
//        cout << setw(2) << setfill('0') << hex << mtx[i].to_ulong() << " ";
//        if ((i + 1) % 4 == 0)
//            cout << endl;
//    }
//    cout << endl;
}

/* GF(2^8)的乘法，為了MixColumn而做 */
byte GFMul(byte a, byte b) {
    byte p = 0;
    byte hi_bit_set;
    for (int counter = 0; counter < 8; counter++) {
        if ((b & byte(1)) != 0) {
            p ^= a;
        }
        hi_bit_set = (byte) (a & byte(0x80));
        a <<= 1;
        if (hi_bit_set != 0) {
            a ^= 0x1b; /* x^8 + x^4 + x^3 + x + 1 */
        }
        b >>= 1;
    }
    return p;
}

/* MixColumn，基本上就是代公式 */
void MixColumns(byte mtx[4 * 4]) {
//    cout << "+++++ 開始 MixColumns +++++" << endl;
//    for (int i = 0; i < 16; ++i) {
//        cout << setw(2) << setfill('0') << hex << mtx[i].to_ulong() << " ";
//        if ((i + 1) % 4 == 0)
//            cout << endl;
//    }

    byte arr[4];
    for (int i = 0; i < 4; ++i) {

        for (int j = 0; j < 4; ++j) {
            arr[j] = mtx[i + j * 4];
        }

        mtx[i] = GFMul(0x02, arr[0]) ^ GFMul(0x03, arr[1]) ^ arr[2] ^ arr[3];
        mtx[i + 4] = arr[0] ^ GFMul(0x02, arr[1]) ^ GFMul(0x03, arr[2]) ^ arr[3];
        mtx[i + 8] = arr[0] ^ arr[1] ^ GFMul(0x02, arr[2]) ^ GFMul(0x03, arr[3]);
        mtx[i + 12] = GFMul(0x03, arr[0]) ^ arr[1] ^ arr[2] ^ GFMul(0x02, arr[3]);
    }

//    cout << "----- 結束 MixColumns -----" << endl;
//    for (int i = 0; i < 16; ++i) {
//        cout << setw(2) << setfill('0') << hex << mtx[i].to_ulong() << " ";
//        if ((i + 1) % 4 == 0)
//            cout << endl;
//    }
//    cout << endl;
}

/* AddRoundKey，就是XOR不解釋 */
void AddRoundKey(byte mtx[16], word k[4]) {
//    cout << "+++++ 開始 AddRoundKey +++++" << endl;
//    for (int i = 0; i < 16; ++i) {
//        cout << setw(2) << setfill('0') << hex << mtx[i].to_ulong() << " ";
//        if ((i + 1) % 4 == 0)
//            cout << endl;
//    }
//    cout << "/////// addRoundKey 收到的key(尚待轉置矩陣) ////// " << endl;
//    cout << hex << k[0].to_ulong() << endl;
//    cout << hex << k[1].to_ulong() << endl;
//    cout << hex << k[2].to_ulong() << endl;
//    cout << hex << k[3].to_ulong() << endl;

    // 這邊就是在分別抓取Byte(8bits)，待會要做XOR
    byte tmp_byte[16];
    for (int i = 0; i < 4; ++i) {
        word k1 = k[i] >> 24;
        word k2 = (k[i] << 8) >> 24;
        word k3 = (k[i] << 16) >> 24;
        word k4 = (k[i] << 24) >> 24;

        tmp_byte[i + 0] = byte(k1.to_ulong());
        tmp_byte[i + 4] = byte(k2.to_ulong());
        tmp_byte[i + 8] = byte(k3.to_ulong());
        tmp_byte[i + 12] = byte(k4.to_ulong());
    }

//    cout << "\\\\\\\\\\\\ addRoundKey 收到的key轉置處理後 \\\\\\\\\\\\" << endl;
//    for (int i = 0; i < 16; ++i) {
//        cout << setw(2) << setfill('0') << hex << tmp_byte[i].to_ulong() << " ";
//        if ((i + 1) % 4 == 0)
//            cout << endl;
//    }

    // 開始做XOR
    for (int i = 0; i < 16; ++i) {
        mtx[i] = mtx[i] ^ tmp_byte[i];
    }

//    cout << "----- 結束 AddRoundKey -----" << endl;
//    for (int i = 0; i < 16; ++i) {
//        cout << setw(2) << setfill('0') << hex << mtx[i].to_ulong() << " ";
//        if ((i + 1) % 4 == 0)
//            cout << endl;
//    }
//    cout << endl;
}

/* 基本上就是SubByte的反函數，簡單查表即可 */
void InvSubBytes(byte mtx[4 * 4]) {
//    cout << "+++++ 開始 Inverse SubByte +++++" << endl;
//    for (int i = 0; i < 16; ++i) {
//        cout << setw(2) << setfill('0') << hex << mtx[i].to_ulong() << " ";
//        if ((i + 1) % 4 == 0)
//            cout << endl;
//    }

    for (int i = 0; i < 16; ++i) {
        int row = mtx[i][7] * 8 + mtx[i][6] * 4 + mtx[i][5] * 2 + mtx[i][4];
        int col = mtx[i][3] * 8 + mtx[i][2] * 4 + mtx[i][1] * 2 + mtx[i][0];
        mtx[i] = inv_s_box_ary[row][col];
    }

//    cout << "----- 結束 Inverse SubByte -----" << endl;
//    for (int i = 0; i < 16; ++i) {
//        cout << setw(2) << setfill('0') << hex << mtx[i].to_ulong() << " ";
//        if ((i + 1) % 4 == 0)
//            cout << endl;
//    }
}

/* ShiftRow的反函數，解密時用的，就是往右shift回來即可 */
void InvShiftRows(byte mtx[4 * 4]) {
//    cout << "+++++ 開始 Inverse ShiftRows +++++" << endl;
//    for (int i = 0; i < 16; ++i) {
//        cout << setw(2) << setfill('0') << hex << mtx[i].to_ulong() << " ";
//        if ((i + 1) % 4 == 0)
//            cout << endl;
//    }

    // 第二列右移一位
    byte temp = mtx[7];
    for (int i = 3; i > 0; --i)
        mtx[i + 4] = mtx[i + 3];
    mtx[4] = temp;
    // 第二列右移二位
    for (int i = 0; i < 2; ++i) {
        temp = mtx[i + 8];
        mtx[i + 8] = mtx[i + 10];
        mtx[i + 10] = temp;
    }
    // 第二列右移三位
    temp = mtx[12];
    for (int i = 0; i < 3; ++i)
        mtx[i + 12] = mtx[i + 13];
    mtx[15] = temp;

//    cout << "----- 結束 Inverse ShiftRows -----" << endl;
//    for (int i = 0; i < 16; ++i) {
//        cout << setw(2) << setfill('0') << hex << mtx[i].to_ulong() << " ";
//        if ((i + 1) % 4 == 0)
//            cout << endl;
//    }
}

/* MixColumns的反函數，基本上是一個矩陣運算的公式，簡單代入即可 */
void InvMixColumns(byte mtx[4 * 4]) {
//    cout << "+++++ 開始 Inverse MixColumn +++++" << endl;
//    for (int i = 0; i < 16; ++i) {
//        cout << setw(2) << setfill('0') << hex << mtx[i].to_ulong() << " ";
//        if ((i + 1) % 4 == 0)
//            cout << endl;
//    }

    byte tmp_arr[16];
    for (int i = 0; i < 16; ++i) {
        tmp_arr[i] = mtx[i];
    }
    for (int i = 0; i < 4; ++i) {
        mtx[i] = GFMul(0x0e, tmp_arr[i + 0]) ^ GFMul(0x0b, tmp_arr[i + 4]) ^ GFMul(0x0d, tmp_arr[i + 8]) ^ GFMul(0x09, tmp_arr[i + 12]);
        mtx[i + 4] = GFMul(0x09, tmp_arr[i + 0]) ^ GFMul(0x0e, tmp_arr[i + 4]) ^ GFMul(0x0b, tmp_arr[i + 8]) ^ GFMul(0x0d, tmp_arr[i + 12]);
        mtx[i + 8] = GFMul(0x0d, tmp_arr[i + 0]) ^ GFMul(0x09, tmp_arr[i + 4]) ^ GFMul(0x0e, tmp_arr[i + 8]) ^ GFMul(0x0b, tmp_arr[i + 12]);
        mtx[i + 12] = GFMul(0x0b, tmp_arr[i + 0]) ^ GFMul(0x0d, tmp_arr[i + 4]) ^ GFMul(0x09, tmp_arr[i + 8]) ^ GFMul(0x0e, tmp_arr[i + 12]);
    }

//    cout << "----- 結束 Inverse MixColumn -----" << endl;
//    for (int i = 0; i < 16; ++i) {
//        cout << setw(2) << setfill('0') << hex << mtx[i].to_ulong() << " ";
//        if ((i + 1) % 4 == 0)
//            cout << endl;
//    }
}

/* To make 4 bytes into a word(32bits) */
word Word(byte &k1, byte &k2, byte &k3, byte &k4) {
    word result(0x00000000);
    word temp;
    temp = k1.to_ulong();  // K1
    temp <<= 24;
    result |= temp;
    temp = k2.to_ulong();  // K2
    temp <<= 16;
    result |= temp;
    temp = k3.to_ulong();  // K3
    temp <<= 8;
    result |= temp;
    temp = k4.to_ulong();  // K4
    result |= temp;
    return result;         // (K1, K2, K3, K4) (MSB --> LSB)
}

/* Called by KeyExpansion, just simply left shift (e.g., From [a0, a1, a2, a3] to [a1, a2, a3, a0]) */
word RotWord(word rw) {
    word high = rw << 8;
    word low = rw >> 24;
    return high | low;
}

/* A simple S-BOX look-up called by KeyExpand */
word SubWord(word sw) {
    word temp;
    for (int i = 0; i < 32; i += 8) {
        int row = sw[i + 7] * 8 + sw[i + 6] * 4 + sw[i + 5] * 2 + sw[i + 4];
        int col = sw[i + 3] * 8 + sw[i + 2] * 4 + sw[i + 1] * 2 + sw[i];
        byte val = s_box_ary[row][col];
        for (int j = 0; j < 8; ++j)
            temp[i + j] = val[j];
    }
    return temp;
}

/* KeyExpansion */
void KeyExpansion(byte key[4 * Nk], word w[4 * (Nr + 1)]) {
    // 基本上照著原文書上的Pseudo code打就不會有問題了
    word temp;
    for(int i = 0; i < 4; ++i) {
        w[i] = Word(key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]);
    }
    for(int i = 4; i < 44; ++i) {
        temp = w[i - 1];
        if (i % Nk == 0) {
            w[i] = w[i - Nk] ^ SubWord(RotWord(temp)) ^ Rcon[i / Nk - 1];
        } else {
            w[i] = w[i - Nk] ^ temp;
        }
    }

}

/* AES-Encryption */
void encrypt(byte in[4 * 4], word w[4 * (Nr + 1)]) {

    word key[4];
    for (int i = 0; i < 4; ++i)
        key[i] = w[i];
    AddRoundKey(in, key);

    cout << "S" << 0 << "： ";
    for (int i = 0; i < 4; ++i) {
        for(int j = 0; j < 4; ++j) {
            cout << setw(2) << setfill('0') << hex << in[i + 4*j].to_ulong() << " ";
        }
    }
    cout << endl;

    for (int round = 1; round < Nr; ++round) {
        SubBytes(in);//
        ShiftRows(in);//
        MixColumns(in);//

        // To update the new key (From KeyExpansion)
        for (int i = 0; i < 4; ++i)
            key[i] = w[4 * round + i];

        AddRoundKey(in, key);

        cout << "S" << round << "： ";
        for (int i = 0; i < 4; ++i) {
            for(int j = 0; j < 4; ++j) {
                cout << setw(2) << setfill('0') << hex << in[i + 4*j].to_ulong() << " ";
            }
        }
        cout << endl;
    }

    SubBytes(in);
    ShiftRows(in);

    // To update the new key (From KeyExpansion)
    for (int i = 0; i < 4; ++i)
        key[i] = w[4 * Nr + i];

    AddRoundKey(in, key);
}

/* AES-Decryption */
void decrypt(byte in[4 * 4], word w[4 * (Nr + 1)]) {
    word key[4];
    for (int i = 0; i < 4; ++i)
        key[i] = w[40 + i];
    AddRoundKey(in, key);

    cout << "S'" << 0 << "： ";
    for (int i = 0; i < 4; ++i) {
        for(int j = 0; j < 4; ++j) {
            cout << setw(2) << setfill('0') << hex << in[i + 4*j].to_ulong() << " ";
        }
    }
    cout << endl;

    for (int round = 1; round < Nr; ++round) {
        InvShiftRows(in);
        InvSubBytes(in);

        // 更新本輪會用到的Key, 因為解密時Key的順序與加密時剛好是相反的，故index存取較麻煩 (即，從尾到頭)
        for (int i = 0; i < 4; ++i)
            key[3 - i] = w[39 - 4*(round - 1) - i];

        AddRoundKey(in, key);
        InvMixColumns(in);

        cout << "S'" << round << "： ";
        for (int i = 0; i < 4; ++i) {
            for(int j = 0; j < 4; ++j) {
                cout << setw(2) << setfill('0') << hex << in[i + 4*j].to_ulong() << " ";
            }
        }
        cout << endl;
    }

    InvShiftRows(in);
    InvSubBytes(in);

    // 更新本輪會用到的Key, 因為解密時Key的順序與加密時剛好是相反的，故index存取較麻煩 (即，從尾到頭)
    for (int i = 0; i < 4; ++i)
        key[i] = w[i];

    AddRoundKey(in, key);
}
