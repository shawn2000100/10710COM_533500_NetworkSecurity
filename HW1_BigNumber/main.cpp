#include <iostream>
#include <string>
#include "Big_Number_Class.h"
using namespace std;

string split_input_name(string);  // e.g., split "varX=" to "varX" (pop_back)
void hex_to_ascii(string &);      // e.g., "f124" to ascii value "63, 49, 50, 52"

int main() {
    /*********************************************************
      sample input:
      a= f1245ab3341ff3461818881767676819ee
      b= ffa24387539639853800bbecbcb494990

      to avoid the tricky testcase, such as:

        g= f12345
        b= f111
            or
        x1= f12345
        x3= 1234f

      we have to store both the varName and the varValue
     *********************************************************/
    string input1_name, input1_value; // varName1, varValue1
    string input2_name, input2_value; // varName2, varValue2
    while(cin >> input1_name >> input1_value
              >> input2_name >> input2_value) {
        // e.g., "varX=" becomes "varX"
        input1_name = split_input_name(input1_name);
        input2_name = split_input_name(input2_name);

        /*** now we initialize the BigNumber Class for further calculation ***/
        bool sign = true; // + true, - false
        unsigned int number_of_bits = input1_value.length();
        // deal with the negative number
        if(input1_value[0] == '-') {
            sign = false;
            number_of_bits = number_of_bits - 1;
        }

        // Because the inputs are supposed to be HEX, however the ASCII value of 0 ~ 9 and a ~ f are very different
        // e.g., '0':48, '9':57, 'a':97, 'b':98... (They are far apart each other, so we have to deal with that situation)
        // e.g., the ASCII velue of input: "f123a" will become [63, 49, 50, 51, 58] (for the convenience of future calculation)
        hex_to_ascii(input1_value);
        BigNumber big_number_A(sign, number_of_bits, (uint8_t*) (input1_value + '\0').c_str()); // we have to add '\0' in the last!!

        /***  Another initialization for input2, the same as above one ***/
        sign = true; // + true, - false
        number_of_bits = input2_value.length();
        if(input2_value[0] == '-') {
            sign = false;
            number_of_bits = number_of_bits - 1;
        }
        hex_to_ascii(input2_value);
        BigNumber big_number_B(sign, number_of_bits, (uint8_t*) (input2_value + '\0').c_str()); // we have to add '\0' in the last!!


        /*** this two lines are just for debug and assure our data ***/
//        big_number_A.getClassInformation();
//        big_number_B.getClassInformation();


        /*** we just complete the initialization. now it's time to start our calculation! ***/
        BigNumber big_number_C;

        // add
        big_number_C = big_number_A + big_number_B;
//        big_number_C.getClassInformation();
        cout << input1_name << "+" << input2_name << " = ";
        big_number_C.getValue();

        // minus
        big_number_C = big_number_A - big_number_B;
//        big_number_C.getClassInformation();
        cout << input1_name << "-" << input2_name << " = ";
        big_number_C.getValue();

        // multiply
        big_number_C = big_number_A * big_number_B;
//        big_number_C.getClassInformation();
        cout << input1_name << "*" << input2_name << " = ";
        big_number_C.getValue();

        // divide
        big_number_C = big_number_A / big_number_B;
//        big_number_C.getClassInformation();
        cout << input1_name << "/" << input2_name << " = ";
        big_number_C.getValue();

        // mod
        big_number_C = big_number_A % big_number_B;
//        big_number_C.getClassInformation();
        cout << input1_name << "%" << input2_name << " = ";
        big_number_C.getValue();

        /*** so far, we have done everything! just remember to reset the input string for next calculation ***/
        input1_name.clear(), input1_value.clear();
        input2_name.clear(), input2_value.clear();
    }

    return 0;
}


/*** e.g., split "varX=" to "varX" (pop_back) ***/
string split_input_name(string input){
//    input.pop_back(); // because some compiler may not support this (C++11), so i removed this function
    input = input.substr(0, input.length() - 1);
    return input;
}

/*** e.g., "f124" to ascii value "63, 49, 50, 52"
 * Note: we have to use pass-by-reference, otherwise the string won't be changed!
***/
void hex_to_ascii(string &input){
    int len = input.length();
    for(int i = 0; i < len; ++i){
        if(input[i] == 'a' || input[i] == 'A'){
            input[i] = 58;
        } else if(input[i] == 'b' || input[i] == 'B'){
            input[i] = 59;
        } else if(input[i] == 'c' || input[i] == 'C'){
            input[i] = 60;
        } else if(input[i] == 'd' || input[i] == 'D'){
            input[i] = 61;
        } else if(input[i] == 'e' || input[i] == 'E'){
            input[i] = 62;
        } else if(input[i] == 'f' || input[i] == 'F'){
            input[i] = 63;
        }
    }
}
