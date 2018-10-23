#include <iostream>
#include <cstring>
#include <algorithm>
#include "Big_Number_Class.h"
using namespace std;

/*** Because I failed to find the reverse library, so i do this by myself ***/
void string_reverse(uint8_t *data, int len){
    for(int i = 0; i < len / 2; ++i){
        swap(data[i], data[len - 1 - i]);
    }
}

/*** because the data type is uint8_t, so i can't use strlen() library... ***/
int string_length(uint8_t *data){
    int i = MAX_LEN - 1;
    while(data[i] == '\0' && i > 0){ // Note: in case of zero length string (e.g., 0), we have to add  condition ( && i > 0)
        --i;
    }
    return i + 1; // remember the array index start from 0
}

/*** cmp(A, B) == true, if A >= B, and vice versa. This function is usually used in minus operation ***/
bool compare_data(uint8_t *dataA, int lenA, uint8_t *dataB, int lenB){
    bool result = true;

    // because all inputs are positive, we simply compare the data length
    if(lenA < lenB){
        result = false;
    }
        // if two data are equal length, we have to compare each digit from the MSB to LSB
        // remember, data[0], data[1]... represent the MSB (We didn't send a reverse data string to this function)
    else if(lenA == lenB){
        for(int i = 0; i < lenA; ++i){
            if(dataA[i] > dataB[i]){ // A > B
                break;
            } else if(dataA[i] < dataB[i]){ // A < B
                result = false;
                break;
            } else if(dataA[i] == dataB[i]){
                continue; // this line is redundant. i just want to say, if A[i] == B[i], we keep comparing
            }
        }
    }

    return result;
}

/***  ***/
bool compare_data(string dataA, string dataB){
    bool result = true;

    // because all inputs are positive, we simply compare the data length
    if(dataA.length() < dataB.length()){
        result = false;
    }
    // if two data are equal length, we have to compare each digit from the MSB to LSB
    // remember, data[0], data[1]... represent the MSB (We didn't send a reverse data string to this function)
    else if(dataA.length() == dataB.length()){
        for(int i = 0; i < dataA.length(); ++i){
            if(dataA[i] > dataB[i]){ // A > B
                break;
            } else if(dataA[i] < dataB[i]){ // A < B
                result = false;
                break;
            } else if(dataA[i] == dataB[i]){
                continue; // this line is redundant. i just want to say, if A[i] == B[i], we keep comparing
            }
        }
    }

    return result;
}

/*** ***/
void reduce_zero(string &str){
    int i = 0;
    for( ; i < str.length(); ++i){
        if(str[i] != 0){
            break;
        }
    }

    if(i == str.length()){
        str = "";
    }else{
        str = str.substr(i);
    }
}

/***  ***/
string multiply_for_division(int coeff, string str){
    int result_int[MAX_LEN];
    for(int i = 0; i < MAX_LEN; ++i) {
        result_int[i] = 0;
    }

    /*** now we reverse data to get LSB --> MSB ***/
    reverse(str.begin(), str.end());
    for(int i = 0; i < str.length(); ++i){
        result_int[i] = result_int[i] + coeff * (str[i] - '0');
    }
    for(int i = 0; i < str.length(); ++i){
        result_int[i + 1] = result_int[i + 1] + result_int[i] / 16;
        result_int[i] = result_int[i] % 16;
    }

    // clean the array, make sure there is no redundant zero
    int pos = str.length();
    for( ; pos >= 0; --pos){
        if(result_int[pos] != 0){
            break;
        }
    }

    string result;
    for(int i = 0; i <= pos; ++i){
        result = result + (char) (result_int[i] + '0');
    }
    reverse(result.begin(), result.end()); // don't forget we reversed this string before
    return  result;
}

/*** remember the strA always >= strB ***/
string subtract_for_division(string A, string B){

    string result;

    /*** minus from LSB to MSB ***/
    for(int i = A.length() - 1; i >= 0; --i){
        result = result + (char) ((A[i] - '0') - (B[i] - '0'));
    }

    // deal with the borrow_in (處理進位)
    for(int i = 0; i < A.length() - 1; ++i){
        if(result[i] < 0){
            result[i] = result[i] + 16;
            result[i + 1] = result[i + 1] - 1;
        }
    }

    reverse(result.begin(), result.end());
    reduce_zero(result);
    for(int i = 0; i < result.length(); ++i){
        result[i] = result[i] + '0';
    }
    return result;
}

/*** the default constructor of BigNumber Class ***/
BigNumber::BigNumber(void) {
    this->sign = true;
    this->number_of_bits = 0;
    this->data[0] = '0';
    this->data[1] = '\0';
}

/*** this only used in divide operation ***/
BigNumber::BigNumber(unsigned long long int value) {
    this->sign = true;
    int len = 0;
    while(value >= 1){
        this->data[len++] = value % 16 + '0';
        value = value / 16;
    }
    this->number_of_bits = len;
    string_reverse(this->data, len);
    this->data[len] = '\0';
}

/*** Another constructor. if we want to set the value of some BigNumber Class  ***/
BigNumber::BigNumber(bool sign, unsigned int number_of_bits, uint8_t *data) {
    this->sign = sign;
    this->number_of_bits = number_of_bits;

    // if the input is negative
    if(data[0] == '-'){
        for(int i = 0; i < number_of_bits + 1; ++i) // the "+ 1" is very important!, we want to add '\0' inside the data string
            this->data[i] = data[i + 1];
    }
        // if the input is positive
    else {
        for(int i = 0; i < number_of_bits + 1; ++i) // the "+ 1" is very important!, we want to add '\0' inside the data string
            this->data[i] = data[i];
    }
}

/*** in the divide operation, sometimes we want to know which BigNumber is bigger ***/
bool BigNumber::operator>=(BigNumber B) {
    bool result = true;

    if(this->number_of_bits == B.number_of_bits){
        if( compare_data(this->data, this->number_of_bits, B.data, B.number_of_bits) == false ){
            result = false;
        }
    }
    else if(this->number_of_bits < B.number_of_bits){
        result = false;
    }

    return result;
}

/*** Add ***/
BigNumber BigNumber::operator+(BigNumber B) {
    /**********************************************************************
     * for calculation, I firstly copy dataA, dataB, and then reverse them
     * second, I declare another big array to store the computing result
     * then, we use iteration to start our computing (Remember, every data will minus '0'(48) in this step )
     * add ASCII value '0'(48) back
     * last, we reverse the data back (MSB --> LSB), and then return the new BigNumber Class (the answer)
     **********************************************************************/
    int lenA = this->number_of_bits, lenB = B.number_of_bits;
    int maxLen = max(lenA, lenB); // this variable is important for iteration
    uint8_t tmpA[lenA + 1];       // remember to +1, to store the '\0'
    uint8_t tmpB[lenB + 1];       // remember to +1, to store the '\0'

    memcpy(tmpA, this->data, lenA + 1); // remember to +1, to copy the '\0'
    memcpy(tmpB, B.data, lenB + 1);     // remember to +1, to copy the '\0'
    string_reverse(tmpA, lenA); // for convenience, we reverse the data. Then the (LSB) will be from index[0] to index[n] (MSB)
    string_reverse(tmpB, lenB); // for convenience, we reverse the data. Then the (LSB) will be from index[0] to index[n] (MSB)

    /*** now, we declare another uint8_t array for storing computing results ***/
    uint8_t tmpC[MAX_LEN];
    memset(tmpC, '\0', MAX_LEN);


    /*** we start to compute each summing digitC
     * Note: it's better that we separate summing process and carry-out process, instead of calculating them together.
    ***/
    for(int i = 0; i < maxLen; ++i){
        int bitA = 0;
        if(i < lenA){ // we want to make sure the index is not out of range
            bitA = tmpA[i] - '0';
        }
        int bitB = 0;
        if(i < lenB){ // we want to make sure the index is not out of range
            bitB = tmpB[i] - '0';
        }

        tmpC[i] = tmpC[i] + bitA + bitB;
    }
    // then we calculate the carry out
    for(int i = 0; i < maxLen; ++i){
        tmpC[i + 1] = tmpC[i + 1] + tmpC[i] / 16;
        tmpC[i] = tmpC[i] % 16;
    }


    /*** Because our type is uint8_t(unsigned char), so we have to add ASCII '0' again, to properly show the results ***/
    int lenC = string_length(tmpC); // the length of calculation result
    for(int i = 0; i < lenC; ++i){
        tmpC[i] = tmpC[i] + '0';
    }


    /*** Last, we reverse the data to properly show the result (MSB --> LSB), and then return the new BigNumber Class ***/
    string_reverse(tmpC, lenC);
    BigNumber big_answer(true, lenC, tmpC);
    return big_answer;
}

/*** Minus ***/
BigNumber BigNumber::operator-(BigNumber B) {
    /**********************************************************************
     * for minus calculation, first we want to compare two equations to know which one is bigger.
     * (Note: all input are positive, so we don't need to worry about -A minus -B ...etc)
     *
     * there are three situations:
     * --------------------------
     * bigger - smaller = + (A - B)
     * smaller - bigger = - (B - A)
     * same - same = + ("0")
     * --------------------------
     *
     * To sum up, we have to first compare the equations, and determine the sign(+, -)
     * Then, we reverse each data string to calculate them
     * Last, we reverse it back.
     **********************************************************************/
    int lenA = this->number_of_bits, lenB = B.number_of_bits;
    int maxLen = max(lenA, lenB); // this variable is important for iteration
    uint8_t tmpA[maxLen + 1];     // remember to +1, to store the '\0'
    uint8_t tmpB[maxLen + 1];     // remember to +1, to store the '\0'

    /*** we compare the equality and then let bigger one always be on the top ***/
    bool sign = compare_data(this->data, lenA, B.data, lenB);
    /* bigger - smaller */
    if(sign){
        memcpy(tmpA, this->data, lenA + 1); // remember to +1, to copy the '\0'
        memcpy(tmpB, B.data, lenB + 1);     // remember to +1, to copy the '\0'
    }
        /* smaller - bigger */
    else{
        swap(lenA, lenB); // we now swap the lenA, lenB. let bigger one on the top (for convenience calculation)
        memcpy(tmpA, B.data, lenA + 1);
        memcpy(tmpB, this->data, lenB + 1);
    }


    /*** As usual, we reverse both string to conveniently compute the results ***/
    string_reverse(tmpA, lenA);
    string_reverse(tmpB, lenB);

    // this one is for storing computing results
    uint8_t tmpC[MAX_LEN];
    memset(tmpC, '\0', MAX_LEN);


    /*** we start to compute each minus digitC ***/
    int borrow_in = 0;
    for(int i = 0; i < maxLen; ++i){
        int bitA = 0;
        if(i < lenA){ // we want to make sure the index is not out of range
            bitA = tmpA[i] - '0';
        }
        int bitB = 0;
        if(i < lenB){ // we want to make sure the index is not out of range
            bitB = tmpB[i] - '0';
        }

        int bitC = bitA - bitB - borrow_in; // Note: because tmpC is an uint8_t data type, so we have to declare another int to store minus number
        if(bitC < 0){ // this may happen when A is smaller than B
            bitC = bitC + 16;
            borrow_in = 1;
        } else{       // when A - B > 0, we don't need to borrow in any number
            borrow_in = 0;
        }

        tmpC[i] = bitC;
    }


    /*** Because our type is uint8_t(unsigned char), so we have to add '0' again to properly show the results ***/
    int lenC = string_length(tmpC);
    for(int i = 0; i < lenC; ++i){
        tmpC[i] = tmpC[i] + '0';
    }


    /*** Last, we reverse the data to properly show the result (MSB --> LSB), and then return the new BigNumber Class ***/
    string_reverse(tmpC, lenC);
    BigNumber big_answer(sign, lenC, tmpC);
    return big_answer;
}

/*** Multiply ***/
BigNumber BigNumber::operator*(BigNumber B) {
    /**********************************************************************
     * for calculation, I firstly copy dataA, dataB,
     * judge the sign of result (++, --: true  -+ +-: false)
     * reverse two tmp arrays of inputs
     * second, I declare another big array to store the computing result
     * then, we use iteration to start our computing (Remember, every data will minus '0'(48) in this step )
     * add ASCII value '0'(48) back
     * last, we reverse the data back (MSB --> LSB), and then return the new BigNumber Class (the answer)
     **********************************************************************/
    int lenA = this->number_of_bits, lenB = B.number_of_bits;
    int maxLen = lenA + lenB + 1; // Note: A * B may result at most (A + B)digits. For safety, I add 1
    uint8_t tmpA[maxLen + 1];     // remember to +1, to store the '\0'
    uint8_t tmpB[maxLen + 1];     // remember to +1, to store the '\0'
    memcpy(tmpA, this->data, lenA + 1); // remember to +1, to copy the '\0'
    memcpy(tmpB, B.data, lenB + 1);     // remember to +1, to copy the '\0'


    /*** first we judge the sign, despite the input are all positive... (++ --: true, -+ +-: false) ***/
    bool sign = true;
    if( (this->data[0] == '-' && B.data[0] != '-') || (this->data[0] != '-' && B.data[0] == '-') ){
        sign = false;
    }


    /*** As usual, we reverse both string to conveniently compute the results ***/
    string_reverse(tmpA, lenA);
    string_reverse(tmpB, lenB);


    // this one is for storing computing results
    // Note: because the multiplication result is huge, we use int array to store the multiplication result
    int tmpResult_int_t[MAX_LEN];
    /*************************************************************
     * memset(tmpResult_int_t, 0, MAX_LEN);
     * e04！ 超大一個坑，memset出來的陣列不是0!!  don't use this function!!
     *************************************************************/
    for(int i = 0; i < MAX_LEN; ++i){
        tmpResult_int_t[i] = 0;
    }


    /*** Before start our calculation, we first minus '0'(48) ***/
    for(int i = 0; i < lenA; ++i){
        tmpA[i] = tmpA[i] - '0';
    }
    for(int j = 0; j < lenB; ++j){
        tmpB[j] = tmpB[j] - '0';
    }


    /*** we start to compute each multiply digitC ***/
    for(int j = 0; j < lenB; ++j){
        for(int i = 0; i < lenA; ++i){
            int digitA = tmpA[i];
            int digitB = tmpB[j];
            int digitC = (digitA * digitB);
            tmpResult_int_t[j + i] = tmpResult_int_t[j + i] + digitC;
        }
    }

    /*** this may be useful when debug ***/
//    cout << "test after multiply: " << endl;
//    for(int i = 0; i < maxLen; ++i){
//        cout << (int) tmpResult_int_t[i] << " ";
//    }
//    cout << endl;


    /*** After multiplication, we also have to deal with the carry_out (處理進位) ***/
    for (int i = 0; i < maxLen; ++i) {
        if(tmpResult_int_t[i] >= 16){
            tmpResult_int_t[i + 1] = tmpResult_int_t[i + 1] + tmpResult_int_t[i] / 16;
            tmpResult_int_t[i] = tmpResult_int_t[i] % 16;
        }
    }

    /*** this may be useful when debug ***/
//    cout << "test after adjust: " << endl;
//    for(int i = 0; i < maxLen; ++i){
//        cout << (int) tmpResult_int_t[i] << " ";
//    }
//    cout << endl;


    /*** Remember we use int array to temporarily store the multiplication result,
     * so now we have to copy it to uint8_t array
    ***/
    uint8_t tmpC[MAX_LEN];
    memset(tmpC, '\0', MAX_LEN);
    for(int i = 0; i < maxLen; ++i){
        tmpC[i] = (char) tmpResult_int_t[i];
    }

    /*** this may be useful when debug ***/
//    cout << "test after copy: " << endl;
//    for(int i = 0; i < maxLen; ++i){
//        cout << (int) tmpC[i] << " ";
//    }
//    cout << endl;


    /*** Because our type is uint8_t(unsigned char), so we have to add '0' again to properly show the results ***/
    int lenC = string_length(tmpC);
    for(int i = 0; i < lenC; ++i){
        tmpC[i] = tmpC[i] + '0';
    }


    /*** Last, we reverse the data to properly show the result (MSB --> LSB), and then return the new BigNumber Class ***/
    string_reverse(tmpC, lenC);
    BigNumber big_answer(sign, lenC, tmpC);
    return big_answer;
}

/*** Divide ***/
BigNumber BigNumber::operator/(BigNumber B) {
    int lenA = this->number_of_bits;
    int lenB = B.number_of_bits;
    // e.g., 1 /2 = 0
    if(lenA < lenB){
        BigNumber big_answer;
        return  big_answer;
    }


    /*** copy, done ***/
    string inputA;
    for(int i = 0; i < this->number_of_bits; ++i){
        inputA = inputA + (char) this->data[i];
    }
    string inputB;
    for(int i = 0; i < B.number_of_bits; ++i){
        inputB = inputB + (char) B.data[i];
    }
    string tmpResult;


    /*** the most difficult part!! ***/
    int idx = lenB;
    int iteration_times = 0;
    string tmpA = inputA.substr(0, lenB);
    while(lenB + iteration_times <= lenA){

        if(compare_data(tmpA, inputB)){
            for(int i = 15; i >= 1; --i){
                if( compare_data(tmpA, multiply_for_division(i, inputB)) ){
                    tmpA = subtract_for_division(tmpA, multiply_for_division(i, inputB)); // current tmpA - i * B
                    tmpResult = tmpResult + (char) (i + '0'); // This is quotient
                    reduce_zero(inputA);
                    break;
                }
            }
        }else{
            tmpResult = tmpResult + '0';
        }

        reduce_zero(tmpA);
        tmpA = tmpA + inputA[idx];
        ++idx;
        ++iteration_times;
    }
    // sometimes there is some dirty '0' in the head of data string
    int i = 0;
    for( ; i < tmpResult.length(); ++i){
        if(tmpResult[i] != '0'){
            break;
        }
    }
    tmpResult = tmpResult.substr(i);


    /*** ***/
    uint8_t ans[MAX_LEN];
    for(int i = 0; i < MAX_LEN; ++i)
        ans[i] = 0;
    for(int i = 0; i < tmpResult.length(); ++i){
        ans[i] = tmpResult[i];
    }
    BigNumber big_answer(true, tmpResult.length(), ans);
    return big_answer;
}

/*** Mod ***/
BigNumber BigNumber::operator%(BigNumber B) {
    /**********************************************************************
     * in mod operation, we simply reuse the divide operation
     *
     * A = quotient x B + residual
     * quotient = A / B
     *
     * So we obtain: residual = A - (quotient) x B
     **********************************************************************/
    BigNumber tmpA(this->sign, this->number_of_bits, this->data);
    BigNumber tmpB(B.sign, B.number_of_bits, B.data);
    BigNumber big_answer = tmpA - (tmpA / tmpB) * tmpB;
    return big_answer;
}

/*** for conveniently debug ***/
void BigNumber::getClassInformation(void) {
    char sgn = '+';
    if(this->sign == false){
        sgn = '-';
    }

    /* a :, b ;, c <, d =, e >, f ? */
    cout << "---------- Class Information ----------" << endl;
    cout << "Sign: " << sgn << endl;
    cout << "Number of bits: " << this->number_of_bits << endl;
    cout << "ASCII value: " << this->data << endl; // because HEX, so sometimes this string may looks weird
    cout << "---------- ----------------- ----------" << endl << endl;
}

/*** I should say, this is "Print Data" ***/
void BigNumber::getValue(void){

    /*** First we copy the data of this Class ***/
    uint8_t tmp[MAX_LEN];
    memcpy(tmp, this->data, sizeof(this->data));

    /*** Then we want to show the ASCII character of the data
     * Remember the ASCII value of 'a', is far different from '9', so we have to do this convert
    ***/
    for(int i = 0; i < MAX_LEN - 1; ++i){
        if(tmp[i] >= 58 && tmp[i] <= 63){
            tmp[i] = 'a' + tmp[i] - 58;
        }
    }

    /*** now we judge the sign, to decide whether print the '-' or not ***/
    if(this->sign == true){
        if(this->number_of_bits == 0){
            cout << "0" << endl;
        }
        else{
            cout << tmp << endl;
        }
    } else {
        cout << '-' << tmp << endl;
    }
}











