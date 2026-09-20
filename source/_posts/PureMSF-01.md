---
title: PureMSF-01
date: 2026-09-21 00:25:00 +08:00
tags:
  - 样本分析
  - MSF
categories:
  - 木马分析
---

# PureMSF-01

## 文件信息

md5：AB5F81E7C0A95737A74829CB837625DF

编译时间：2026-07-02 18:07:58

![image](/img/PureMSF-01/image-20260705200250-ppyvby0.png)

## 静态分析

### 字符串查看

![image](/img/PureMSF-01/image-20260712202854-4v1xrud.png)

同时hex-view里也能看到一些信息

winint、http请求格式、/DFne、103.146.231.107

![image](/img/PureMSF-01/image-20260712203025-xz5mcdn.png)

该ip对应的威胁情报

![image](/img/PureMSF-01/image-20260712203210-zb8erda.png)

### 导入/导出表查看

导出表只有一个start函数

![image](/img/PureMSF-01/image-20260712202924-iu602kv.png)

![image](/img/PureMSF-01/image-20260712202935-t3wq5ur.png)

### 函数

这里只有三个函数信息

![image](/img/PureMSF-01/image-20260712203257-djts7ei.png)

#### Start

查看伪代码 。

这里看着很奇怪。直接看反汇编吧

![image](/img/PureMSF-01/image-20260712202109-r9dwxg9.png)

反汇编代码

![image](/img/PureMSF-01/image-20260712204936-h5bwpor.png)

74656E696E6977h转换成ascii就是teniniw（小端存储），一个用于网络通信的dll。

![image](/img/PureMSF-01/image-20260712205019-1o2diw1.png)

![image](/img/PureMSF-01/image-20260712205201-d745x7t.png)

这里首先清空rsp，然后传入rcx（wininet）和r10(0DEC21CCDh)给115c函数（一个解析apihash的函数）

![image](/img/PureMSF-01/image-20260712211015-vum4k0z.png)

接着去找这个hash对应的windows函数363799Dh

![image](/img/PureMSF-01/image-20260712211219-zjunyz8.png)

这里跟到去看下resolve_api_by_hash这个函数内容

就是通过peb寻址的方式对比事先计算好的api的hash，找到指定api并调用。

![image](/img/PureMSF-01/image-20260712211416-s28fyi9.png)

![image](/img/PureMSF-01/image-20260712211434-b7y0b5m.png)

![image](/img/PureMSF-01/image-20260712211657-o9pur1a.png)

这里通过动态调试找一下这两个hash是什么吧

在关键函数点按tab转到反汇编

![image](/img/PureMSF-01/image-20260712215301-f87lhxw.png)

根据这个地址减去基地址计算出rva。这里是11E6

![image](/img/PureMSF-01/image-20260712215310-5u6ysh4.png)

然后到x64dbg里面，ctrl+G：demo1+11E6（这里直接进入判断成功的条件里）

可以看到rsi里面存的就是loadlibrary。

![image](/img/PureMSF-01/image-20260712212325-3tj5cj7.png)

最后却是调用的也是loadlibrary，rcx中保存的是要加载的模块，wininet.dll

![image](/img/PureMSF-01/image-20260712215609-9roxudg.png)

执行结束该dll也被加载到当前进程中

![image](/img/PureMSF-01/image-20260712215816-e40iki0.png)

然后找第二个hash相关的函数，这里定位到了InternetopenUrlA函数

![image](/img/PureMSF-01/image-20260712215927-6p2b6jv.png)

```c
HINTERNET InternetOpenUrlA(
 [in] HINTERNET hInternet,
 [in] LPCSTR lpszUrl,
 [in] LPCSTR lpszHeaders,
 [in] DWORD dwHeadersLength,
 [in] DWORD dwFlags,
 [in] DWORD_PTR dwContext
);
```

接着执行loc_140001145，然后这边有一个空指令什么也不做，执行到loc_140001147，然后先call了loc_140001049

![image](/img/PureMSF-01/image-20260712220819-v3wvmps.png)

这里也是一个解析apihash的，去找0x2289ACBA

![image](/img/PureMSF-01/image-20260712220956-91f84wh.png)

![image](/img/PureMSF-01/image-20260712221516-0iqqipy.png)

```c
HINTERNET InternetConnectW(
  [in] HINTERNET     hInternet,
  [in] LPCWSTR       lpszServerName,
  [in] INTERNET_PORT nServerPort,
  [in] LPCWSTR       lpszUserName,
  [in] LPCWSTR       lpszPassword,
  [in] DWORD         dwService,
  [in] DWORD         dwFlags,
  [in] DWORD_PTR     dwContext
);	
```

![image](/img/PureMSF-01/image-20260712221605-gs8ggmm.png)![image](/img/PureMSF-01/image-20260712222402-ca2l9bk.png)

后续就是一些网络请求

![image](/img/PureMSF-01/image-20260712222620-u19ejze.png)

![image](/img/PureMSF-01/image-20260712222637-9n0lgwk.png)

![image](/img/PureMSF-01/image-20260712222558-9xnolnx.png)

![image](/img/PureMSF-01/image-20260712222721-3lcrqqk.png)

‍

![image](/img/PureMSF-01/image-20260712222756-6c0ewr5.png)

```c
 2. _LDR_DATA_TABLE_ENTRY 在 x64 下的布局

  偏移(结构体)  字段
  0x00        InLoadOrderLinks           LIST_ENTRY  (16 字节)
  0x10        InMemoryOrderLinks         LIST_ENTRY  ← i 指向这里
  0x20        InInitializationOrderLinks LIST_ENTRY
  0x30        DllBase                    PVOID
  0x38        EntryPoint                 PVOID
  0x40        SizeOfImage                ULONG + 4字节填充
  0x48        FullDllName.Length         USHORT
  0x4A        FullDllName.MaxLength      USHORT
  0x4C        (4 字节对齐填充)
  0x50        FullDllName.Buffer         PWSTR
  0x58        BaseDllName.Length         USHORT  ← 就是这个!
  0x5A        BaseDllName.MaxLength      USHORT
  0x5C        (4 字节填充)
  0x60        BaseDllName.Buffer         PWSTR


 IMAGE_EXPORT_DIRECTORY 布局:
  偏移    字段                    大小    含义
  0x00   Characteristics         DWORD
  0x04   TimeDateStamp           DWORD
  0x08   MajorVersion            WORD
  0x0A   MinorVersion            WORD
  0x0C   Name                    DWORD   (DLL 名字符串的 RVA)
  0x10   Base                    DWORD   (ordinal 起始基数,一般是 1)
  0x14   NumberOfFunctions       DWORD   (AddressOfFunctions 数组大小)
  0x18   NumberOfNames           DWORD   ★ 导出名的数量
  0x1C   AddressOfFunctions      DWORD   (RVA → 函数地址数组)
  0x20   AddressOfNames          DWORD   ★ (RVA → 函数名指针数组)
  0x24   AddressOfNameOrdinals   DWORD   (RVA → ordinal 数组)


  1. 遍历 AddressOfNames 找到哈希匹配的 i
  2. ordinal = AddressOfNameOrdinals[i]
  3. funcRVA = AddressOfFunctions[ordinal]
  4. funcAddr = base + funcRVA
```
