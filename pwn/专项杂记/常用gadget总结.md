---

title: 常用gadget总结

date: 2025-11-06 23:52:39

tags: pwn

categories: ctf学习

---

### Systemcall 相关

  

1.`pop rax; ret;` 可以用来调整 syscall 的调用函数

  

执行 `syscall` 时，CPU 会根据寄存器里的值进入内核态，并执行相应的系统调用。

关键寄存器如下：

  
  

| 寄存器  | 含义                         |

| ------- | ---------------------------- |

| **rax** | 系统调用号（syscall number） |

| **rdi** | 第一个参数                   |

| **rsi** | 第二个参数                   |

| **rdx** | 第三个参数                   |

| **r10** | 第四个参数                   |

| **r8**  | 第五个参数                   |

| **r9**  | 第六个参数                   |

  

不同的系统调用号对应不同的函数：

  
  

| 系统调用 | 编号 (x86\_64) | 说明       |

| -------- | -------------- | ---------- |

| read     | 0              | 从文件读取 |

| write    | 1              | 写入文件   |

| open     | 2              | 打开文件   |

| execve   | 59             | 执行程序   |

  

举个例子：

  

execve("/bin/sh", 0, 0)

  

在 x86\_64 上：

  

```cpp

rax = 59          ; execve 的 syscall 编号

rdi = "/bin/sh"   ; 第一个参数：文件路径

rsi = 0           ; 第二个参数：argv

rdx = 0           ; 第三个参数：envp

syscall           ; 执行系统调用

```

**注意**: 不要混淆`system`和`systemcall`,
`system()` 是 libc（glibc）提供的普通函数，其作用是：
`system(const char *cmd)`
内部会做：
1. fork()
2. execve("/bin/sh", ["sh", "-c", cmd])
3. 等待子进程结束

它是 **复杂的高级 API**。
`systemcall`如上为系统内核级调用.