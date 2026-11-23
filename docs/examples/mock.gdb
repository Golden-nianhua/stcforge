# 无需硬件的完整往返示例。服务端使用 --mock --once 启动。
set pagination off
set confirm off
set architecture mcs251
set endian big
target remote 127.0.0.1:3333
info registers r0 wr16 spx pc
x/2bx 0x30
stepi
print/x $pc
break *0xff0002
continue
print/x $pc
delete breakpoints
detach
quit
