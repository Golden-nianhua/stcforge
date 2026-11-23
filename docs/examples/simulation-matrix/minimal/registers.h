#ifndef MINIMAL_MATRIX_REGISTERS_H
#define MINIMAL_MATRIX_REGISTERS_H

#include <stdint.h>

/* Addresses copied from the validated SDCC Simulation Test register headers.
 * Self-contained: no original driver/global-state implementation is linked. */
#define XFR(address) (*(volatile uint8_t __far *)(address))
__sfr __at(0x89) TMOD;
__sfr __at(0x8B) TL1;
__sfr __at(0x8D) TH1;
__sfr __at(0x8E) AUXR;
__sfr __at(0x8F) INTCLKO;
__sfr __at(0xBA) P_SW2;
__sfr __at(0xE9) WTST;
__sfr __at(0xEA) CKCON;
__sbit __at(0x8F) TF1;
__sbit __at(0x8E) TR1;
__sbit __at(0xAB) ET1;
__sbit __at(0xAF) EA;

#define CLKSEL    XFR(0x7EFE00UL)
#define CLKDIV    XFR(0x7EFE01UL)
#define IRC48MCR  XFR(0x7EFE07UL)
#define TM1PS     XFR(0x7EFEA1UL)
#define P9INTE    XFR(0x7EFD09UL)
#define P_SWX5    XFR(0x7EFD6DUL)
#define TM7PS     XFR(0x7EFBB8UL)
#define T8T7CFG   XFR(0x7EFBBAUL)
#define T8T7M     XFR(0x7EFBBBUL)
#define T7H       XFR(0x7EFBBEUL)
#define T7L       XFR(0x7EFBBFUL)
#define P9PU      XFR(0x7EF9C1UL)
#define P9NCS     XFR(0x7EF9C9UL)
#define P9IE      XFR(0x7EF9E1UL)
#define P9PD      XFR(0x7EF9F1UL)
#define P9BP      XFR(0x7EF9F9UL)
#define P9M0      XFR(0x7EF711UL)
#define P9M1      XFR(0x7EF719UL)
#define P9SETB    XFR(0x7EF721UL)
#define P9CLRB    XFR(0x7EF729UL)
#define S7CON     XFR(0x7EF7A0UL)
#define S7BUF     XFR(0x7EF7A1UL)
#define S7INTR    XFR(0x7EF7A2UL)
#define UR7TOCR   XFR(0x7EF7A4UL)
#define USART7CR1 XFR(0x7EF7A8UL)
#define USART7CR2 XFR(0x7EF7A9UL)
#define S7CFG     XFR(0x7EF7CDUL)

#endif
