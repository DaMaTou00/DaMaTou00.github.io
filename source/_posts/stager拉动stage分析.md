---
title: 文章标题
date: 2026-09-20 23:47:00
tags:
  - Cobaltstrike原生马分析
categories:
  - 木马分析
---
# stager 拉动stage分析

通过分析前面的stager，已经获取到解密后的shellcode，下面是对shellcode的分析内容。

首先将df标志位清零，然后将rsp进行16字节对齐，接着调用9500D2这个函数

![image](/img/stager拉动stage分析/image-20260507213517-ay2hf28.png)

这里首先把函数的返回地址交给了rbp，然后压入了 0，r14（0074656E696E6977）两个参数。

接着把该字符串地址保存在rcx寄存器中，然后又给r10保存了一个000000000726774C。

然后直接call rbp

![image](/img/stager拉动stage分析/image-20260507214257-m2c3mxf.png)

0074656E696E6977代表的就是wininet.这个字符串。

![image](/img/stager拉动stage分析/image-20260507213953-6wm1n00.png)

这里一共传了三个参数（wininet地址,wininet字符串,0）给000000000065000A ，r10里面还保存了000000000726774。

保存寄存器并且清空rdx

![image](/img/stager拉动stage分析/image-20260507215456-dhuayyb.png)

dt _peb

![image](/img/stager拉动stage分析/image-20260507222137-32f20oq.png)

​`dt ntdll!_PEB_LDR_DATA poi(@$peb+18)`

0x20偏移为`InMemoryOrderModuleList `其中保存的是双向链表的地址。

![image](/img/stager拉动stage分析/image-20260507222256-i9yeoif.png)

双向链表的每一个链表结构为`_LDR_DATA_TABLE_ENTRY`​，`InMemoryOrderLinks`为第一个链表的0x10偏移

因此`dt ntdll!_LDR_DATA_TABLE_ENTRY (poi(poi(@$peb+18)+20) - 10)`可以得到链表结构的首地址

在该结构的0x58处的到basedllname与长度

![image](/img/stager拉动stage分析/image-20260507232319-dwbs2p9.png)

![image](/img/stager拉动stage分析/image-20260507232342-wv21iq6.png)

以上对应如下

![image](/img/stager拉动stage分析/image-20260507232409-l2uxr7m.png)

获取到当前链表的basedllname后，对该名称转换成大写，然后再把每一位右移D位的结果累加到r9里面

![image](/img/stager拉动stage分析/image-20260507232805-s65rto1.png)

最终得到

000000008A8D78CC，f.exe名称转换成一串加密的字符的结果。

紧接着这里压栈rdx(模块基地址)和r9(模块名称加密后的字符串)

找到pe头的偏移，然后接着取到文件头里面的**Magic，判断是否为20b(64位程序)**

接着取到了文件头里面的数据目录[0]也就是导出表的地址，但是该值为0，后续跳转至6500c7

![image](/img/stager拉动stage分析/image-20260507235244-qviikdh.png)

首先弹出r9和rdx，然后把rdx中保存的值给rdx，跳转到650021

![image](/img/stager拉动stage分析/image-20260507235713-67h03cb.png)

这里得到ntdll，依旧进行上述循环

![image](/img/stager拉动stage分析/image-20260507235849-y0w5cdz.png)

最终得到ntdll的编码000000003E9A174F

![image](/img/stager拉动stage分析/image-20260508000019-37x5rxt.png)

接着还是判断是否含有导出表，因为这里是ntdll，接着初始化一些导出表的信息。

![image](/img/stager拉动stage分析/image-20260508003155-7g21jh3.png)

这里主要从后往前，把ntdll里导出函数的名称进行右移编码，保存结果到r9d里面，因为函数名字符串会以00结尾，用cmp al，ah来判断一个函数的结束，

mov esi, dword ptr ds:[r8+rcx*4]  
这里r8是函数名称表的首地址，一个函数是四字节，rcx * 4 就是代表最后一个函数的首地址。通过这种方式不仅可以控制循环还可以寻址。

![image](/img/stager拉动stage分析/image-20260508003308-zy25f2v.png)

紧接着这里把r9（函数hash）和rsp+8的值相加（模块hash），并与r10d进对比。

![image](/img/stager拉动stage分析/image-20260508004243-kp1ny19.png)

这里r10就是第一步里面保存的000000000726774C一个编码。

这里查看esi可知就是loadlibraryExA这个函数。

![image](/img/stager拉动stage分析/image-20260508005427-8kboe33.png)

接着就是利用获取到的函数名称序号根据序号表去找对应函数的地址。最终获取到loadlibraryEax的地址

![image](/img/stager拉动stage分析/image-20260508013657-do1wuhj.png)

调用loadlibrary

![image](/img/stager拉动stage分析/image-20260508020948-1w7vai5.png)

![image](/img/stager拉动stage分析/image-20260508021116-ilqkpna.png)

调用InternetOpenA

![image](/img/stager拉动stage分析/image-20260508021229-3ypb2nz.png)

调用InternetconnectA

恶意域名192.168.21.130

![image](/img/stager拉动stage分析/image-20260508021724-p9z9nbz.png)

HINTERNET InternetConnectA(  
  HINTERNET hInternet,  
  LPCSTR    lpszServerName,   // ⭐ 服务器域名  
  INTERNET_PORT nServerPort,  
  LPCSTR    lpszUserName,  
  LPCSTR    lpszPassword,  
  DWORD     dwService,  
  DWORD     dwFlags,  
  DWORD_PTR dwContext  
);

‍

‍

调用![image](/img/stager拉动stage分析/image-20260508021822-e3dtrq7.png)

恶意uri /hRn5

![image](/img/stager拉动stage分析/image-20260508021812-ysik9tc.png)

![image](/img/stager拉动stage分析/image-20260508021851-merhgfe.png)

virtualalloc 0000000003E60000

![image](/img/stager拉动stage分析/image-20260508022456-2daa1s8.png)

![image](/img/stager拉动stage分析/image-20260508022716-d3a05x1.png)

![image](/img/stager拉动stage分析/image-20260508022740-6vv8v03.png)426

4260000 4261ff0

总体逻辑

1. 对齐栈，建立 API resolver
2. 从 PEB 遍历模块链表
3. 解析模块导出表
4. 用 ROR13 hash 找 API
5. 先找 kernel32!LoadLibraryA
6. LoadLibraryA("wininet")
7. 继续通过 hash 调用 wininet.dll 里的网络 API
8. 建立连接 / 打开请求 / 发送请求 / 读取下一阶段数据
