#ifndef HW1_BIGNUMBER_BIG_NUMBER_CLASS_H
#define HW1_BIGNUMBER_BIG_NUMBER_CLASS_H
#define MAX_LEN 256
typedef unsigned char uint8_t;

class BigNumber {
private:
    bool sign; // + true, - false
    unsigned int number_of_bits;
    uint8_t data[MAX_LEN];

public:
    BigNumber(void);                          // default constructor, initialize a (+, 0, "0") BigNumber class
    BigNumber(unsigned long long int);                           // directly convert from an int value
    BigNumber(bool, unsigned int, uint8_t *); // setting the BigNumber class by this constructor

    bool operator >= (BigNumber);     // in the divide operation, we will use this comparison symbol
    BigNumber operator + (BigNumber);
    BigNumber operator - (BigNumber);
    BigNumber operator * (BigNumber);
    BigNumber operator / (BigNumber);
    BigNumber operator % (BigNumber);

    void getClassInformation(void); // we want to know all the BigNumber Class information. This function is useful for debug
    void getValue(void);            // only print the data of BigNumber class, in (uint8_t) type. We use this function to show the calculation answer
};

#endif //HW1_BIGNUMBER_BIG_NUMBER_CLASS_H
