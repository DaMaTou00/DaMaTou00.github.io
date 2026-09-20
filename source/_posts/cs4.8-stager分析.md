---
title: CS 木马分析 - 4.8 stager
date: 2026-09-20 23:26:00
tags:
  - 安全
  - 木马分析
categories:
  - 学习笔记
---
# 4.8 stager分析

## 判断是否加壳

显示用c++开发，未加壳

![image](/assets/image-20260429001828-yiwoczv.png)

![image](/assets/image-20260429002351-lx8ybbc.png)

## 导入表分析

这里导入了命名管道创建与连接，创建文件，进程枚举，内存分配与属性修改等函数

大体也能猜到做了管道shellcode拷贝，环境监测，分配内存，创建线程执行shellcode的操作

![image](/assets/image-20260429002852-xr22i7v.png)

用idapro静态分析，找到主函数start，跟进函数**sub_401990();**

![image](/assets/image-20260429002146-bhuc4of.png)

这里主要生成一个随机的值result

![image](/assets/image-20260429223831-9cbdos2.png)

在伪代码窗口按f4还原汇编，找到返回值result这里的内存地址，在 401a49

![image](/assets/image-20260429224952-b52t2ij.png)

在这个地方下个断点，动态调试获取到result的值为0000D18F42C0F9DE

![image](/assets/image-20260429224826-yg94ul1.png)

这个值暂时没看到有什么用，继续下一个函数sub_401180

开始是一些初始化的信息

![image](/assets/image-20260429231219-qs7aod5.png)

这里有一个tls回调相关但是没看懂，回调里面也没有做什么操作

![image](/assets/image-20260429233828-c7nmto5.png)

继续往下看，这里有一个memcpy的调用

![image](/assets/image-20260429233707-pdqv70b.png)

但是动态调试并没有发现这里拷贝了什么关键信息

![image](/assets/image-20260429233712-kt2a9tg.png)

跟进最后一个函数sub_403040()

![image](/assets/image-20260429233920-184muh6.png)

先看sub_401950();

这里调用了一个函数指针，没看懂在干什么

![image](/assets/image-20260429234040-sypqyjs.png)

看第二个函数sub_4017F8()

先获取一个随机数，然后拼接了一个命名管道，接着创建一个线程运行函数sub_4016E6

![image](/assets/image-20260429234257-p6yqsxy.png)

创建的命名管道

![image](/assets/image-20260429235037-7u6b8ie.png)

跟进sub_4016E6函数中的sub_401630，这里传入两个参数，根据函数中的具体描述可以得到，第一个是要拷贝的内存首地址，第二个是要拷贝的大小

![image](/assets/image-20260429234513-aa89kaj.png)

这里开始创建一个命名管道，并进行数据写入。

![image](/assets/image-20260429234537-9zfz3xc.png)

写入大小为037d，893个字节，从04 AF处开始写入

![image](/assets/image-20260430004626-5br1k7w.png)

此处为加密的shellcode

![image](/assets/image-20260430004711-pqb8ugt.png)

跟进函数sub_4017A6()

![image](/assets/image-20260430004839-81x06mi.png)

sub_401704，读管道dest中的内容到v2 中

![image](/assets/image-20260430004848-wrdnuus.png)

sub_401595创建线程，先对shellcode进行解密，然后将解密后的shellcode写入到分配的内存空间，接着修改  
内存属性，创建线程执行shellcode，这里CreateThread传入的第四个参数是v6，也就是shellcode的地址空间。

StartAddress为一个函数指针执行的函数。

```java
HANDLE CreateThread(
 LPSECURITY_ATTRIBUTES lpThreadAttributes, //线程安全属性定义 NUll
 SIZE_T dwStackSize,                       //初始堆栈大小 0
 LPTHREAD_START_ROUTINE lpStartAddress,    //线程函数指针（要运行的函数）
 LPVOID lpParameter,                       //传递的参数
 DWORD dwCreationFlags                     //控制线程创建，0为立即执行，CREATE_SUSPENDED为挂起
 LPDWORD lpThreadId                        //线程id
);
```

![image](/assets/image-20260430004857-58fgfw2.png)

sub_401563函数主要用于保存GetModuleHandleA和GetProcAddress的内存地址。

startAddress函数

![image](/assets/image-20260430153316-679qpvm.png)

该函数传参逻辑如下

```java
HANDLE CreateThread(
  LPSECURITY_ATTRIBUTES   lpThreadAttributes, // 第1参数 -> RCX
  SIZE_T                  dwStackSize,        // 第2参数 -> RDX
  LPTHREAD_START_ROUTINE  lpStartAddress,     // 第3参数 -> R8 (线程函数地址)
  LPVOID                  lpParameter,        // 第4参数 -> R9 (传给线程的参数)
  DWORD                   dwCreationFlags,    // 第5参数 -> 栈
  LPDWORD                 lpThreadId          // 第6参数 -> 栈
);
```

通过查看函数调用时，R9的内存地址即可获取shellcode，在0000000000650000

![image](/assets/image-20260430153831-enty90b.png)

同时也可以查看virtualalloc函数的执行返回值 RAX。

这里可以通过右键--复制到反汇编，找到virtualalloc函数在内存中的执行地址。

![image](/assets/image-20260430004947-na7srqf.png)

进入动态调试后，在这里下断点，然后观察rax的值（virtualalloc分配的内存空间）

![image](/assets/image-20260430005058-1fh3x6x.png)

利用dbg命令​`savedata filename.bin, 0000000000650000, 37D`

​`savedata <保存文件名>，<起始地址>，<大小>`

查看字符串可以看到ua头，ip地址等信息。

该shellcode 会请求192.168.21.130/HWDz来下载程序

![image](/assets/image-20260430005240-ibt6jkp.png)

‍
