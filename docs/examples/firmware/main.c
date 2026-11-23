/* 符号联调夹具：只用于编译/离线测试，不会自动烧录。 */
volatile __xdata unsigned int counter = 0x1234;
volatile __xdata unsigned long ticks = 0x89abcdefUL;
static volatile unsigned char ready = 1;
__sfr __at(0xa8) IE;

void probe(void)
{
    counter++;
    ticks++;
    ready = !ready;
}

void main(void)
{
    for (;;) {
        probe();
    }
}
