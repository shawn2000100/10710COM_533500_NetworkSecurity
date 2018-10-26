#include <iostream>
#include <cstdio>
#include <string>
#include <bitset>
#include <iomanip>

using namespace std;
typedef unsigned char      uint8_t;
typedef unsigned short int uint16_t;
typedef bitset<8> byte;
typedef bitset<32> word;
const int Nr = 10;  // AES-128需要 10 轮加密
const int Nk = 4;   // Nk 表示输入密钥的 word 个数

uint8_t s_box_ary[16][16] = {0};
uint8_t inv_s_box_ary[16][16] = {0};
word Rcon[10] = {0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
                 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000};

void input_func(uint8_t *input);
/******************** for the s-box generation ***********************/
uint16_t polynomialMutil(uint8_t a, uint8_t b);
uint8_t findHigherBit(uint16_t val);
uint8_t gf28_div(uint16_t div_ed, uint16_t div, uint16_t *remainder);
uint8_t extEuclidPolynomial(uint8_t a, uint16_t m);
uint8_t uint8_tTransformation(uint8_t a, uint8_t x);
uint8_t invuint8_tTransformation(uint8_t a, uint8_t x);
void s_box_gen(void);
void inv_s_box_gen(void);

/******************************下面是加密的变换函数**********************/
void SubBytes(byte mtx[4*4]);
void ShiftRows(byte mtx[4*4]);
byte GFMul(byte a, byte b);
void MixColumns(byte mtx[4*4]);
void AddRoundKey(byte mtx[16], word k[4]);

/**************************下面是解密的逆变换函数***********************/
void InvSubBytes(byte mtx[4*4]);
void InvShiftRows(byte mtx[4*4]);
void InvMixColumns(byte mtx[4*4]);
word Word(byte& k1, byte& k2, byte& k3, byte& k4);
word RotWord(word rw);
word SubWord(word sw);
void KeyExpansion(byte key[4*Nk], word w[4*(Nr+1)]);

/******************************下面是加密和解密函数**********************/
void encrypt(byte in[4*4], word w[4*(Nr+1)]);
void decrypt(byte in[4*4], word w[4*(Nr+1)]);


/***
Sample input: // ilms老師給的sample input
Plaintext: a3 c5 08 08 78 a4 ff d3 00 ff 36 36 28 5f 01 02
Key:       36 8a c0 f4 ed cf 76 a6 08 a3 b6 78 31 31 27 6e

// 原文書上的範例輸入
Plaintext: 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
Key:       0f 15 71 c9 47 d9 e8 59 0c b7 ad d6 af 7f 67 98

// web
Plaintext: 32 88 31 e0 43 5a 31 37 f6 30 98 07 a8 8d a2 34
Key:       2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
 ***/
int main() {
    uint8_t tmp_plain[16] = {0};
    uint8_t tmp_key[16] = {0};
    input_func(tmp_plain);
    input_func(tmp_key);
    s_box_gen();
    inv_s_box_gen();

    /* 把uint8_t 轉成 Byte型態 */
    byte plain[16];
    for(int i = 0; i < 16; ++i){
        plain[i] = tmp_plain[i];
    }
    byte key[16];
    for(int i = 0; i < 16; ++i){
        key[i] = tmp_key[i];
    }

    // 測試plaintext 和 key 是否接收正確無誤
    cout << "PLAIN IS: ";
    for(int i=0; i<16; ++i)
        cout << setw(2) << setfill('0') << hex << plain[i].to_ulong() << " ";
    cout << endl;
    cout << "KEY IS  : ";
    for(int i=0; i<16; ++i)
        cout << setw(2) << setfill('0') << hex << key[i].to_ulong() << " ";
    cout << endl;


    word w[44];
    KeyExpansion(key, w);

    // 测试KeyExpand
    for(int i=0; i<44; ++i)
        cout << "w[" << dec << i << "] = " << setw(8) << setfill('0') << hex << w[i].to_ulong() << endl;
    cout << endl;


    // 加密，输出密文
    encrypt(plain, w);
    cout << "Ciphertext: ";
    for(int i=0; i<16; ++i)
    {
        cout << setw(2) << setfill('0') << hex << plain[i].to_ulong() << " ";
    }
    cout << endl;

    // 測試s-box
//    for(int i = 0; i < 16; ++i){
//        for(int j = 0; j < 16; ++j)
//            cout << hex << (int) s_box_ary[i][j] << " ";
//        cout << endl;
//    }


    return 0;
}


/*************************** 實作部分 *******************************************/
//GF(2^8)的多項式乘法
uint16_t polynomialMutil(uint8_t a, uint8_t b) {
    uint16_t tmp[8] = {0};
    for (uint8_t i = 0; i < 8; i++) {
        tmp[i] = (a << i) * ((b >> i) & 0x1);
    }

    tmp[0] = tmp[0] ^ tmp[1] ^ tmp[2] ^ tmp[3] ^ tmp[4] ^ tmp[5] ^ tmp[6] ^ tmp[7];

    return tmp[0];
}

//找到最高位
uint8_t findHigherBit(uint16_t val) {
    int i = 0;
    while (val) {
        i++;
        val = val >> 1;
    }
    return i;
}

//GF(2^8)的多項式除法
uint8_t gf28_div(uint16_t div_ed, uint16_t div, uint16_t *remainder) {
    uint16_t r0 = 0;
    uint8_t qn = 0;
    int bitCnt = 0;

    r0 = div_ed;

    bitCnt = findHigherBit(r0) - findHigherBit(div);
    while (bitCnt >= 0) {
        qn = qn | (1 << bitCnt);
        r0 = r0 ^ (div << bitCnt);
        bitCnt = findHigherBit(r0) - findHigherBit(div);
    }
    *remainder = r0;
    return qn;
}

//GF(2^8)多項式的擴展歐幾里得算法
uint8_t extEuclidPolynomial(uint8_t a, uint16_t m) {
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
    return w1;
}

//S盒字節變換
uint8_t uint8_tTransformation(uint8_t a, uint8_t x) {
    uint8_t tmp[8] = {0};

    for (uint8_t i = 0; i < 8; i++) {
        tmp[i] = (((a >> i) & 0x1) ^ ((a >> ((i + 4) % 8)) & 0x1) ^ ((a >> ((i + 5) % 8)) & 0x1) ^
                  ((a >> ((i + 6) % 8)) & 0x1) ^ ((a >> ((i + 7) % 8)) & 0x1) ^ ((x >> i) & 0x1)) << i;
    }
    tmp[0] = tmp[0] + tmp[1] + tmp[2] + tmp[3] + tmp[4] + tmp[5] + tmp[6] + tmp[7];
    return tmp[0];
}

//逆S盒字節變換
uint8_t invuint8_tTransformation(uint8_t a, uint8_t x) {
    uint8_t tmp[8] = {0};

    for (uint8_t i = 0; i < 8; i++) {
        tmp[i] = (((a >> ((i + 2) % 8)) & 0x1) ^ ((a >> ((i + 5) % 8)) & 0x1) ^ ((a >> ((i + 7) % 8)) & 0x1) ^
                  ((x >> i) & 0x1)) << i;
    }
    tmp[0] = tmp[0] + tmp[1] + tmp[2] + tmp[3] + tmp[4] + tmp[5] + tmp[6] + tmp[7];
    return tmp[0];
}

//S盒產生
void s_box_gen(void) {

//初始化S盒
    for (uint8_t i = 0; i < 0x10; i++) {
        for (uint8_t j = 0; j < 0x10; j++) {
            s_box_ary[i][j] = ((i << 4) & 0xF0) + (j & (0xF));
        }
    }

//求在GF(2^8)域上的逆，0映射到自身
    for (uint8_t i = 0; i < 0x10; i++) {
        for (uint8_t j = 0; j < 0x10; j++) {
            if (s_box_ary[i][j] != 0) {
                s_box_ary[i][j] = extEuclidPolynomial(s_box_ary[i][j], 0x11B);
            }
        }
    }

//對每個字節做變換
    for (uint8_t i = 0; i < 0x10; i++) {
        for (uint8_t j = 0; j < 0x10; j++) {
            s_box_ary[i][j] = uint8_tTransformation(s_box_ary[i][j], 0x63);
        }
    }

}

//逆S盒產生
void inv_s_box_gen(void) {
//初始化S盒
    for (uint8_t i = 0; i < 0x10; i++) {
        for (uint8_t j = 0; j < 0x10; j++) {
            inv_s_box_ary[i][j] = ((i << 4) & 0xF0) + (j & (0xF));
        }
    }

//對每個字節做變換
    for (uint8_t i = 0; i < 0x10; i++) {
        for (uint8_t j = 0; j < 0x10; j++) {
            inv_s_box_ary[i][j] = invuint8_tTransformation(inv_s_box_ary[i][j], 0x05);
        }
    }

//求在GF(2^8)域上的逆，0映射到自身
    for (uint8_t i = 0; i < 0x10; i++) {
        for (uint8_t j = 0; j < 0x10; j++) {
            if (inv_s_box_ary[i][j] != 0) {
                inv_s_box_ary[i][j] = extEuclidPolynomial(inv_s_box_ary[i][j], 0x11B);
            }
        }
    }

}

void input_func(uint8_t *input){

    // collect input(hex)
    uint8_t temp[49] = {0};
    for(int c = 0; c < 48; c++) {
        temp[c] = getchar();
    }

    // transform to decimal
    for(int c = 0; c < 48; c++){
        if(temp[c] >= '0' && temp[c] <= '9'){
            temp[c] = temp[c] - '0';
        }
        else if(temp[c] >= 'a' && temp[c] <= 'f'){
            temp[c] = temp[c] - 'a' + 10;
        }
        else if(temp[c] >= 'A' && temp[c] <= 'F'){
            temp[c] = temp[c] - 'A' + 10;
        }
    }

    // transform to uint8_t
    for(int i = 0; i < 16; ++i){
        input[i] = 16 * temp[3 * i] + temp[3*i + 1];
    }

}

void SubBytes(byte mtx[4*4])
{
    cout << "inSubBytes = "<< endl;
    for(int i=0; i<16; ++i)
    {
        cout << setw(2) << setfill('0') << hex << mtx[i].to_ulong() << " ";
        if((i+1)%4 == 0)
            cout << endl;
    }
    cout << endl;



    for(int i=0; i<16; ++i)
    {
        int row = mtx[i][7]*8 + mtx[i][6]*4 + mtx[i][5]*2 + mtx[i][4];
        int col = mtx[i][3]*8 + mtx[i][2]*4 + mtx[i][1]*2 + mtx[i][0];
        mtx[i] = s_box_ary[row][col];
    }



    cout << "outSubBytes = "<< endl;
    for(int i=0; i<16; ++i)
    {
        cout << setw(2) << setfill('0') << hex << mtx[i].to_ulong() << " ";
        if((i+1)%4 == 0)
            cout << endl;
    }
    cout << endl;
}

/**
 *  行变换 - 按字节循环移位
 */
void ShiftRows(byte mtx[4*4])
{
    cout << "inShiftRows = "<< endl;
    for(int i=0; i<16; ++i)
    {
        cout << setw(2) << setfill('0') << hex << mtx[i].to_ulong() << " ";
        if((i+1)%4 == 0)
            cout << endl;
    }
    cout << endl;


    // 第二行循环左移一位
    byte temp = mtx[4];
    for(int i=0; i<3; ++i)
        mtx[i+4] = mtx[i+5];
    mtx[7] = temp;
    // 第三行循环左移两位
    for(int i=0; i<2; ++i)
    {
        temp = mtx[i+8];
        mtx[i+8] = mtx[i+10];
        mtx[i+10] = temp;
    }
    // 第四行循环左移三位
    temp = mtx[15];
    for(int i=3; i>0; --i)
        mtx[i+12] = mtx[i+11];
    mtx[12] = temp;


    cout << "outShiftRows = "<< endl;
    for(int i=0; i<16; ++i)
    {
        cout << setw(2) << setfill('0') << hex << mtx[i].to_ulong() << " ";
        if((i+1)%4 == 0)
            cout << endl;
    }
    cout << endl;
}

/**
 *  有限域上的乘法 GF(2^8)
 */
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

/**
 *  列变换
 */
void MixColumns(byte mtx[4*4])
{
    cout << "inMixColumns = "<< endl;
    for(int i=0; i<16; ++i)
    {
        cout << setw(2) << setfill('0') << hex << mtx[i].to_ulong() << " ";
        if((i+1)%4 == 0)
            cout << endl;
    }
    cout << endl;

    // 一樣的寫法
//    byte coeff_matrix[16] = {0x02, 0x03, 0x01, 0x01,
//                             0x01, 0x02, 0x03, 0x01,
//                             0x01, 0x01, 0x02, 0x03,
//                             0x03, 0x01, 0x01, 0x02
//    };
//    byte result[16] = {0};
//    for(int i = 0; i < 4; ++i){
//        for(int j = 0; j < 4; ++j){
//            result[4*i + j]  = GFMul(coeff_matrix[4*i + 0], mtx[j + 0]);
//            result[4*i + j] ^= GFMul(coeff_matrix[4*i + 1], mtx[j + 4]);
//            result[4*i + j] ^= GFMul(coeff_matrix[4*i + 2], mtx[j + 8]);
//            result[4*i + j] ^= GFMul(coeff_matrix[4*i + 3], mtx[j + 12]);
//        }
//    }
//
//    for(int i = 0; i < 16; ++i){
//        mtx[i] = result[i];
//    }


    byte arr[4];
    for(int i=0; i<4; ++i)
    {
        for(int j=0; j<4; ++j)
            arr[j] = mtx[i+j*4];

        mtx[i] = GFMul(0x02, arr[0]) ^ GFMul(0x03, arr[1]) ^ arr[2] ^ arr[3];
        mtx[i+4] = arr[0] ^ GFMul(0x02, arr[1]) ^ GFMul(0x03, arr[2]) ^ arr[3];
        mtx[i+8] = arr[0] ^ arr[1] ^ GFMul(0x02, arr[2]) ^ GFMul(0x03, arr[3]);
        mtx[i+12] = GFMul(0x03, arr[0]) ^ arr[1] ^ arr[2] ^ GFMul(0x02, arr[3]);
    }


    cout << "AfterMixColumns = "<< endl;
    for(int i=0; i<16; ++i)
    {
        cout << setw(2) << setfill('0') << hex << mtx[i].to_ulong() << " ";
        if((i+1)%4 == 0)
            cout << endl;
    }
    cout << endl;
}

/**
 *  轮密钥加变换 - 将每一列与扩展密钥进行异或
 */
void AddRoundKey(byte mtx[16], word k[4])
{
    cout << "inAddRoundKey = "<< endl;
    for(int i=0; i<16; ++i)
    {
        cout << setw(2) << setfill('0') << hex << mtx[i].to_ulong() << " ";
        if((i+1)%4 == 0)
            cout << endl;
    }
    cout << endl;


    cout << "addRoundKey 收到的key = "<< endl;
    cout << hex << k[0].to_ulong() << endl;
    cout << hex << k[1].to_ulong() << endl;
    cout << hex << k[2].to_ulong() << endl;
    cout << hex << k[3].to_ulong() << endl;
    cout << endl;


    byte tmp_w[16];
    for(int i = 0; i < 4; ++i){
        word k1 = k[i] >> 24;
        word k2 = (k[i] << 8) >> 24;
        word k3 = (k[i] << 16) >> 24;
        word k4 = (k[i] << 24) >> 24;

        tmp_w[4*i + 0] = byte(k1.to_ulong());
        tmp_w[4*i + 1] = byte(k2.to_ulong());
        tmp_w[4*i + 2] = byte(k3.to_ulong());
        tmp_w[4*i + 3] = byte(k4.to_ulong());
    }

    for(int i=0; i<16; ++i)
    {
        mtx[i] = mtx[i] ^ tmp_w[i];
    }



    cout << "outAddRoundKey = "<< endl;
    for(int i=0; i<16; ++i)
    {
        cout << setw(2) << setfill('0') << hex << mtx[i].to_ulong() << " ";
        if((i+1)%4 == 0)
            cout << endl;
    }
    cout << endl;
}

/**************************下面是解密的逆变换函数***********************/
/**
 *  逆S盒变换
 */
void InvSubBytes(byte mtx[4*4])
{
    for(int i=0; i<16; ++i)
    {
        int row = mtx[i][7]*8 + mtx[i][6]*4 + mtx[i][5]*2 + mtx[i][4];
        int col = mtx[i][3]*8 + mtx[i][2]*4 + mtx[i][1]*2 + mtx[i][0];
        mtx[i] = inv_s_box_ary[row][col];
    }
}

/**
 *  逆行变换 - 以字节为单位循环右移
 */
void InvShiftRows(byte mtx[4*4])
{
    // 第二行循环右移一位
    byte temp = mtx[7];
    for(int i=3; i>0; --i)
        mtx[i+4] = mtx[i+3];
    mtx[4] = temp;
    // 第三行循环右移两位
    for(int i=0; i<2; ++i)
    {
        temp = mtx[i+8];
        mtx[i+8] = mtx[i+10];
        mtx[i+10] = temp;
    }
    // 第四行循环右移三位
    temp = mtx[12];
    for(int i=0; i<3; ++i)
        mtx[i+12] = mtx[i+13];
    mtx[15] = temp;
}

void InvMixColumns(byte mtx[4*4])
{
    byte arr[4];
    for(int i=0; i<4; ++i)
    {
        for(int j=0; j<4; ++j)
            arr[j] = mtx[i+j*4];

        mtx[i] = GFMul(0x0e, arr[0]) ^ GFMul(0x0b, arr[1]) ^ GFMul(0x0d, arr[2]) ^ GFMul(0x09, arr[3]);
        mtx[i+4] = GFMul(0x09, arr[0]) ^ GFMul(0x0e, arr[1]) ^ GFMul(0x0b, arr[2]) ^ GFMul(0x0d, arr[3]);
        mtx[i+8] = GFMul(0x0d, arr[0]) ^ GFMul(0x09, arr[1]) ^ GFMul(0x0e, arr[2]) ^ GFMul(0x0b, arr[3]);
        mtx[i+12] = GFMul(0x0b, arr[0]) ^ GFMul(0x0d, arr[1]) ^ GFMul(0x09, arr[2]) ^ GFMul(0x0e, arr[3]);
    }
}

/**
 * 将4个 byte 转换为一个 word.
 */
word Word(byte& k1, byte& k2, byte& k3, byte& k4)
{
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
    return result;
}

/**
 *  按字节 循环左移一位
 *  即把[a0, a1, a2, a3]变成[a1, a2, a3, a0]
 */
word RotWord(word rw)
{
    word high = rw << 8;
    word low = rw >> 24;
    return high | low;
}

/**
 *  对输入word中的每一个字节进行S-盒变换
 */
word SubWord(word sw)
{
    word temp;
    for(int i=0; i<32; i+=8)
    {
        int row = sw[i+7]*8 + sw[i+6]*4 + sw[i+5]*2 + sw[i+4];
        int col = sw[i+3]*8 + sw[i+2]*4 + sw[i+1]*2 + sw[i];
        byte val = s_box_ary[row][col];
        for(int j=0; j<8; ++j)
            temp[i+j] = val[j];
    }
    return temp;
}

/**
 *  密钥扩展函数 - 对128位密钥进行扩展得到 w[4*(Nr+1)]
 */
void KeyExpansion(byte key[4*Nk], word w[4*(Nr+1)])
{
    word temp;
    int i = 0;
    // w[]的前4个就是输入的key
    while(i < Nk)
    {
        w[i] = Word(key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]);
        ++i;
    }

    i = Nk;

    while(i < 4*(Nr+1))
    {
        temp = w[i-1]; // 记录前一个word
        if(i % Nk == 0)
            w[i] = w[i-Nk] ^ SubWord(RotWord(temp)) ^ Rcon[i/Nk-1];
        else
            w[i] = w[i-Nk] ^ temp;
        ++i;
    }
}

/******************************下面是加密和解密函数**************************/
/**
 *  加密
 */
void encrypt(byte in[4*4], word w[4*(Nr+1)])
{
//    cout << "in = "<< endl;
//    for(int i=0; i<16; ++i)
//    {
//        cout << setw(2) << setfill('0') << hex << in[i].to_ulong() << " ";
//        if((i+1)%4 == 0)
//            cout << endl;
//    }
//    cout << endl;

    word key[4];
    for(int i=0; i<4; ++i)
        key[i] = w[i];
    AddRoundKey(in, key);

    cout << "S" << 0 << "： ";
    for(int i=0; i<16; ++i)
    {
        cout << setw(2) << setfill('0') << hex << in[i].to_ulong() << " ";
    }
    cout << endl;


    for(int round=1; round<Nr; ++round)
    {
        SubBytes(in);//

        ShiftRows(in);//

        MixColumns(in);//

        for(int i=0; i<4; ++i)
            key[i] = w[4*round+i];


        cout << "key = " << endl;
        cout << hex << key[0].to_ulong() << " ";
        cout << hex << key[1].to_ulong() << " ";
        cout << hex << key[2].to_ulong() << " ";
        cout << hex << key[3].to_ulong() << endl;


        AddRoundKey(in, key);

        cout << "S" << round << "： ";
        for(int i=0; i<16; ++i)
        {
            cout << setw(2) << setfill('0') << hex << in[i].to_ulong() << " ";
        }
        cout << endl;
        break;
    }

    SubBytes(in);
    ShiftRows(in);
    for(int i=0; i<4; ++i)
        key[i] = w[4*Nr+i];

    cout << "key = " << endl;
    cout << hex << key[0].to_ulong() << " ";
    cout << hex << key[1].to_ulong() << " ";
    cout << hex << key[2].to_ulong() << " ";
    cout << hex << key[3].to_ulong() << endl;

    AddRoundKey(in, key);
}

void decrypt(byte in[4*4], word w[4*(Nr+1)])
{
    word key[4];
    for(int i=0; i<4; ++i)
        key[i] = w[4*Nr+i];
    AddRoundKey(in, key);

    for(int round=Nr-1; round>0; --round)
    {
        InvShiftRows(in);
        InvSubBytes(in);
        for(int i=0; i<4; ++i)
            key[i] = w[4*round+i];
        AddRoundKey(in, key);
        InvMixColumns(in);
    }

    InvShiftRows(in);
    InvSubBytes(in);
    for(int i=0; i<4; ++i)
        key[i] = w[i];
    AddRoundKey(in, key);
}