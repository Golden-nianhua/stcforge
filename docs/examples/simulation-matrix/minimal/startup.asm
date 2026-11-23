; Same GSINIT1 stack setup as SDCC Simulation Test.
; This is a fall-through fragment, not a function: do not add RET/ERET.
; GSINIT0 runs first; this sets SPX=00FF before the first C call.
; First stack write is EDATA 000100; real stack uses 000100..003FFF.
    .module board_startup
    .area GSINIT1 (CODE)
    .globl __stc32_stack_init
__stc32_stack_init::
    mov 0x81,#0xFF
    mov 0x85,#0x00
