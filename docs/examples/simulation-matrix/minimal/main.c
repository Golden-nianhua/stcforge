#include "registers.h"

#ifndef MATRIX_VARIANT
#error Define MATRIX_VARIANT as 0, 1, or 2
#endif
#if MATRIX_VARIANT < 0 || MATRIX_VARIANT > 2
#error Invalid MATRIX_VARIANT
#endif

/* No static initializer is used. Every own RAM object is explicitly written
 * in main before its first read; automatic locals are assigned before use. */
volatile __xdata uint8_t led_state;
#if MATRIX_VARIANT == 2
volatile __xdata uint32_t tick_ms;
/* Must be visible in the translation unit containing main for vector emission. */
void timer1_isr(void) __interrupt(3);
#endif

/* C's TWO leading underscores become THREE in the assembler/linker symbol.
 * Return 1 bypasses GSINIT copy/clear; inspect the actual linked startup ABI. */
unsigned char __sdcc_external_startup(void)
{
    EA = 0;
    return 1;
}

static void clock_init(void)
{
    CLKDIV = 10U;
    WTST = 1U;
    CKCON &= 0xF8U;
    IRC48MCR |= 0x80U;
    while ((IRC48MCR & 0x01U) == 0U) { }
    CLKSEL = (CLKSEL & 0xF3U) | 0x0CU;
    CLKDIV = 1U;
}

static void gpio_init(void)
{
    P9CLRB = 0x08U; /* LED P9.3 is active high. */
#if MATRIX_VARIANT == 0
    /* M00 changes only P9.3. P9.0/P9.1 retain their reset configuration. */
    P9BP |= 0x08U;
    P9INTE &= 0xF7U;
    P9PD &= 0xF7U;
    P9PU &= 0xF7U;
    P9NCS &= 0xF7U;
    P9IE |= 0x08U;
    P9M0 = (P9M0 & 0xF7U) | 0x08U;
    P9M1 &= 0xF7U;
#else
    P9SETB = 0x02U; /* UART TX idle high before changing modes. */
    P9BP |= 0x0BU;
    P9INTE &= 0xF4U;
    P9PD &= 0xF4U;
    P9PU = (P9PU & 0xF4U) | 0x01U;
    P9NCS &= 0xF4U;
    P9IE |= 0x0BU;
    P9M0 = (P9M0 & 0xF4U) | 0x0AU;
    P9M1 = (P9M1 & 0xF4U) | 0x01U;
    P_SWX5 = (P_SWX5 & 0xCFU) | 0x20U;
#endif
}

static void led_toggle(void)
{
    led_state ^= 1U;
    if (led_state != 0U) {
        P9SETB = 0x08U;
    } else {
        P9CLRB = 0x08U;
    }
}

#if MATRIX_VARIANT >= 1
static void uart7_init(void)
{
    S7INTR &= 0x7FU; /* UART7 interrupt disabled: polling only. */
    UR7TOCR &= 0x3FU;
    T8T7M &= 0xF0U;
    T8T7CFG &= 0xF6U;
    TM7PS = 0U;
    T8T7M |= 0x02U;
    T7H = 0xFFU;
    T7L = 0x98U; /* IRC48M / (4 * 104), nominal 115200 baud. */
    USART7CR1 = 0U;
    USART7CR2 = 0U;
    S7CFG = (S7CFG & 0x1EU) | 0x01U;
    S7CON = 0x50U;
    T8T7M |= 0x08U;
}

static void uart7_poll(void)
{
    uint8_t value;
    uint16_t spins;
    if ((S7CON & 0x01U) == 0U) {
        return;
    }
    value = S7BUF;
    S7CON &= 0xFEU;
    spins = 60000U;
    S7CON &= 0xFDU;
    S7BUF = value;
    while ((S7CON & 0x02U) == 0U) {
        --spins;
        if (spins == 0U) {
            return; /* Bounded wait, independent of Timer1. */
        }
    }
    S7CON &= 0xFDU;
}
#endif

#if MATRIX_VARIANT < 2
static void software_delay(void)
{
    uint16_t slice;
    volatile uint16_t spins;
    /* Uncalibrated visible delay, identical loop in M00 and M01.
     * M01 polls between slices; UART traffic can lengthen the LED period. */
    for (slice = 0U; slice < 500U; ++slice) {
        for (spins = 0U; spins < 400U; ++spins) {
            __asm nop __endasm;
        }
#if MATRIX_VARIANT == 1
        uart7_poll();
#endif
    }
}
#else
void timer1_isr(void) __interrupt(3)
{
    /* Current backend saves DPL/DPH; explicitly preserve the 24-bit high byte.
     * This ISR has no C calls or automatic local variables. */
    __asm push 0x84 __endasm;
    ++tick_ms;
    __asm pop 0x84 __endasm;
}

static void timer1_init(void)
{
    TR1 = 0;
    ET1 = 0;
    AUXR &= 0xBFU;
    TMOD &= 0x0FU;
    INTCLKO &= 0xFDU;
    TM1PS = 0U;
    TH1 = 0xF0U;
    TL1 = 0x60U; /* 48 MHz / 12 / 1000 = 4000; 16-bit auto reload mode 0. */
    TF1 = 0;
    ET1 = 1;
    TR1 = 1;
}

static uint32_t millis_snapshot(void)
{
    uint8_t saved_ea;
    uint32_t snapshot;
    saved_ea = (uint8_t)EA;
    EA = 0;
    snapshot = tick_ms;
    EA = saved_ea;
    return snapshot;
}
#endif

void main(void)
{
#if MATRIX_VARIANT == 2
    uint32_t now;
    uint32_t last_toggle;
#endif
    EA = 0;
    led_state = 0U;
#if MATRIX_VARIANT == 2
    tick_ms = 0UL;
    last_toggle = 0UL;
#endif
    P_SW2 |= 0x80U;
    gpio_init();
    clock_init();
#if MATRIX_VARIANT >= 1
    uart7_init();
#endif
#if MATRIX_VARIANT == 2
    timer1_init();
    EA = 1;
#endif
    for (;;) {
#if MATRIX_VARIANT == 2
        uart7_poll();
        now = millis_snapshot();
        if ((uint32_t)(now - last_toggle) >= 500UL) {
            last_toggle = now;
            led_toggle();
        }
#else
        software_delay();
        led_toggle();
#endif
    }
}
