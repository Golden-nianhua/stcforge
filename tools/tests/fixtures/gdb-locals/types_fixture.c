struct Node {
    unsigned char id;
    unsigned int payload[2];
    struct Node __xdata *next;
};
union Word {
    unsigned long raw;
    float real;
    unsigned char bytes[4];
};
struct Flags {
    unsigned int mode:3;
    unsigned int ready:1;
    signed int delta:4;
};
struct Reading {
    unsigned int channel;
    float value;
};

__xdata struct Node nodes[2];
__xdata union Word word;
__xdata struct Flags flags;
__xdata unsigned int matrix[2][3];
__xdata float volts;
__xdata float scale;
__xdata unsigned long long wide;
__xdata unsigned int far_value = 0x3456;
__data unsigned char near_value = 0x42;
const __code unsigned char table[] = { 0xa1, 0xb2, 0xc3 };
__xdata unsigned char scratch;
volatile __xdata unsigned int sink;
unsigned int __xdata * __xdata far_ptr = &far_value;
unsigned char __data * __xdata near_ptr = &near_value;
const unsigned char __code * __xdata code_ptr = &table[1];
const unsigned char * __xdata generic_code = &table[0];
unsigned char * __xdata generic_near = &near_value;
unsigned int * __xdata generic_far = &far_value;
static __xdata struct Node hidden;

unsigned int get_value(void)
{
    return sink;
}

unsigned int (* __xdata callback)(void) = get_value;

float get_reading(void)
{
    return scale;
}

void main(void)
{
    union Word local = { 0x3fc00000ul };
    unsigned int samples[2] = { 0x1122, 0x3344 };
    struct Reading measured = { 9, -1.5f };
    float reading = get_reading();
    unsigned int __xdata *ptr = far_ptr;
    sink = get_value() + local.bytes[0] + samples[0] + samples[1] + *ptr;
    volts = reading;
    scale = measured.value;
    sink = measured.channel;
    hidden.id = near_value;
    for (;;) {}
}
