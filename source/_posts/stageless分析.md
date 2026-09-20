---
title: stageless分析
date: 2026-09-21 12:00:00 +08:00
tags:
  - Cobaltstrike无阶段分析
categories:
  - 木马分析
---

# stageless分析

无阶段会将自身一段shellcode自解密完然后进行加载，下面通过bp virtualalloc获取其分配的内存地址来看具体的shellcode内容。

‍

将beacon基地址+0x16EA4 作为一个函数地址进行调用

![image](/img/stageless分析/image-20260518001434-0n2di0j.png)

跟进该函数，把beacon基地址和函数返回地址压入栈

![image](/img/stageless分析/image-20260518001748-tysxrg7.png)

接着对栈做了一些操作，压入了几个立即数，然后做了一些堆栈的清空。紧接着call了

0x00000000006B72D4  
0000000000DDFEC0  4141414141414141  
0000000000DDFEC8  4242424242424242

![image](/img/stageless分析/image-20260518002026-qaqy1pf.png)

0x00000000006B72D4函数

进去创建一个新的堆栈空间然后进入call 0x00000000006B7124

![image](/img/stageless分析/image-20260518002412-aqtxpo4.png)

然后把rax 赋值为00000000006B72DD，当前rsp保存的就是0x00000000006B72D4的返回地址。

![image](/img/stageless分析/image-20260518002501-34amtzq.png)

紧接着带着00000000006B72DD这个值，不断的去进行自减操作操作，直到该值指向的地址内容为4D5A。

![image](/img/stageless分析/image-20260518005126-lh5rbz5.png)

当指向地址内容符合条件时候，接着判断当前地址的3C偏移处（PE头的偏移地址）是否在 40和400之间（一个合理的范围）

如果条件不满足则继续进行地址自减。

![image](/img/stageless分析/image-20260518005447-7oqrbov.png)

这一步就是在寻找加载到内存里的dll文件

![image](/img/stageless分析/image-20260519003603-tbg36v5.png)

这里有一个坑，如果对Beacon的原始地址打断点以后，地址首地址就不是4D5A了，那么就会在这个函数里面找不到Beacon的地址从而报错。。。。

根据PE偏移，进一步验证Beacon地址+pe偏移处的值是否为4550，如果一致，则找到地址了。

将Beacon地址和PE偏移分别保存在Rax和栈中。

![image](/img/stageless分析/image-20260518014752-y57ntur.png)

紧接着的函数没明白在干嘛

这里把，0000000000DBFEC0处值为：4141414141414141传入了下一个函数，通过RCX保存地址

![image](/img/stageless分析/image-20260518015423-1tpx4q3.png)

![image](/img/stageless分析/image-20260518015536-w34d9zo.png)

进入函数6B7364

![image](/img/stageless分析/image-20260519011225-kfdlsws.png)

这里栈保存的数据如下

|rsp|模块名长度|1c|
| ----------| -------------------------| -----------|
|rsp + 20|hash值|0（初始）|
|rsp + 40|模块地址指向的字符|b(初始)|
|rsp+28|InMemoryOrderModuleList|/|

首先根据peb寻址找到当前加载模块，获取到模块名和模块名长度

这里是其本身 beacon_x64.exe，长度为1c。

![image](/img/stageless分析/image-20260519005858-v0sfdux.png)

接着这里会创建一个逻辑

将RSP + 20处的值每次右移D位，运算结果保存在rsp+20的位置，同时rsp+40这里保存的是模块名称的地址。

![image](/img/stageless分析/image-20260519010404-nhy7nqi.png)

接着这部分逻辑，首先把当前模块的每一位转换成大写字符

![image](/img/stageless分析/image-20260519010647-j4bgua8.png)

接着把hash值和当前模块的地址指向的字符进行相加，结果还保存在rsp+20处

![image](/img/stageless分析/image-20260519010808-b9ie7ho.png)

这里截图时候已经运行起来了，可以看到模块地址保存在rsp+40处，指向的是on_..... rax的值是O的大写 4F。

![image](/img/stageless分析/image-20260519010826-oddm4up.png)

然后对当前模块名称的地址进行自减，指向下一个字符。

rsp里面存的是模块名的长度，用来做循环条件，每处理一位减一。

![image](/img/stageless分析/image-20260519011013-m2tw0a4.png)

最后得到一个加密的hash值 000000006ED7C6E5

![image](/img/stageless分析/image-20260519011604-zkzdrks.png)

这段函数的C代码大致如下

```c
uint32_t hash = 0;
uint8_t *p = (uint8_t *)moduleNameBuffer;
uint16_t len = moduleNameLength;  // UNICODE_STRING.Length，单位是字节

for (uint16_t i = 0; i < len; i++) {
    hash = ror32(hash, 13);

    uint8_t ch = p[i];

    if (ch >= 0x61) {
        ch -= 0x20;
    }

    hash += ch;
}
```

接着会匹配这个hash是否为0x6A4ABC5B，如果不是则把InMemoryOrderModuleList保存到rax里，继续进行上述函数。

![image](/img/stageless分析/image-20260519012526-oa5qw4w.png)

这个函数最后找到的dll是kernel32.dll

![image](/img/stageless分析/image-20260519014332-uq3ewgl.png)

00000000006B7457函数

使用过程中堆栈变换如下：

|rsp+8|k32基地址|00007FFFCA220000|
| ----------| ----------------| ------------------|
|rsp+8|pe头|00007FFFCA220100|
|rsp+38|导出表rva|00007FFFCA220188|
|rsp + 30|导出表va|00007FFFCA220100|
|rsp + 38|导出函数名称表|00007FFFCA2C4BC0|
|rsp + 50|导出函数序号表|00007FFFCA2C80D0|
|rsp + 48|导出表va|00007FFFCA2C8E17|
|rsp + 10|函数hash|/|
|18|函数rva||

参考右边注释，这一段主要是找到dll的基地址，然后手动解析dll，获取导出函数表，然后获取到导出函数名称表和序号表

![image](/img/stageless分析/image-20260520015041-08tw7co.png)

![image](/img/stageless分析/image-20260520015359-ol2egve.png)

同时这里设置六次循环

![image](/img/stageless分析/image-20260520015506-8y4ukfy.png)

每次循环主要做的内容，通过获取的函数名称表va和序号表va，遍历每一个函数，同时设置一个右移算法，与之前类似。将每一个函数计算的到一个hash值，然后根据hash值比对找到指定函数。

计算

![image](/img/stageless分析/image-20260520015749-49q1gu1.png)

进行hash比对

![image](/img/stageless分析/image-20260520015903-y1icagr.png)

6b76ba

如果没找到指定hash函数，则修改名称和序号表指向下一个函数。然后重复上述寻找

![image](/img/stageless分析/image-20260520020129-zp8jex7.png)

这里直接在6b7594下断点，这里是每次找到对应hash函数都会跳转的

第一次找到的是GetModuleHandleA 对应hash 00000000D3324904

![image](/img/stageless分析/image-20260520020906-7wuqpsb.png)

接着获取AddressOfFunctions 的地址，然后根据地址序号找到真正对应函数的地址。

换算关系如下图中右侧注释。

![image](/img/stageless分析/image-20260520022139-nbq7708.png)

接着再根据hash进行比对，跳转执行  
​![image](/img/stageless分析/image-20260520022341-vwa5djl.png)

这里对函数进行了保存，首先根据的到的函数地址rva，加上内存pe头的地址，得到va。

接着将地址保存到之前硬编码占位的地方。

![image](/img/stageless分析/image-20260520022739-as7fx5j.png)

原先是用AAAAAABBBBB进行占位的。

![image](/img/stageless分析/image-20260520022853-mitqmue.png)

找到一个函数以后减少一次循环次数，接着重复上述将名称表和序号表指向下一个单元，重复上述计算hash找目标函数的过程。

![image](/img/stageless分析/image-20260520022947-cskbqzq.png)

第二个函数 GetProcAddress hash 000000007C0DFCAA

保存到原先的占位处。qword大小

![image](/img/stageless分析/image-20260520023326-e2vpx5o.png)

第三个函数 LoadLibraryA hash 00000000EC0E4E8E

第四个 LoadLibraryExA  0x753A4FC

第五个  VirtualAlloc 0000000091AFCA54

第六个 VirtualProtect 000000007946C61B

到此 6b7364结束

保存这六个函数到栈中

![image](/img/stageless分析/image-20260520023934-1td9z0n.png)

接着对这几个函数获取的地址进行检查，判断是否为0

![image](/img/stageless分析/image-20260520024217-o6zxhb1.png)

接着开始解析dll

|地址|内容|值|
| ------| -------------| ------------------|
|50|dll文件|00000000006A0000|
|30|pe头的va|00000000006A0110|
|40||40|
|38|新pe地址|720000|
|68|sizeofimage|56000|

从6b6f78开始尝试反射加载自己。

首先解析PE，然后获取characteristics属性，接着和8000进行对比，这里没什么意义，characteristics为0x2000是dll。因此判断失败，进入6b6fb8。

6b6fb8调用了一个函数，传入了如下参数

|r9|40|
| -----| -------------------------------|
|r8|baseaddress|
|pe|va|
|rcx|动态获取的getmodulehandle地址|

![image](/img/stageless分析/image-20260524034428-yxax7ur.png)

![image](/img/stageless分析/image-20260524034809-32lrgva.png)

接着调用6b79a4

对比characteristic属性是否为4000

![image](/img/stageless分析/image-20260524035019-9ulhyta.png)

接着跳到6b7acd，这里主要是调用virtualalloc创建了sizeofimage大小的内存空间。

![image](/img/stageless分析/image-20260524035128-j33unhl.png)

这里可以看到新创建的内存空间在72000

![image](/img/stageless分析/image-20260524035301-5qhpoqo.png)

然后接着把新分配的这块地址空间，按sizeofimage大小清零。

![image](/img/stageless分析/image-20260524035554-q3o0gco.png)

然后读取了pNtHeader->FileHeader.NumberOfSymbols，该值为0.

接着传入

r9 0

r8 baseaddress原本

rdx nt头

rcx 新地址

调用6b7b74

![image](/img/stageless分析/image-20260524040144-f55g0gh.png)

该函数首先计算sizeofheader，然后把原始地址中的pe头拷贝到新分配的空间

![image](/img/stageless分析/image-20260524041535-k36b0f9.png)

![image](/img/stageless分析/image-20260524041614-vva0yut.png)

接着对新地址空间里面的内容进行一些赋0，主要把DOS头标志，eflanew，nt头表示全部清零。

![image](/img/stageless分析/image-20260524042435-azer1b2.png)

完事又调用函数6b7c34

传入

r9 0000000000D1FEB0

r8 baseaddress

rdx nt头（原始）

rcx 新地址。

![image](/img/stageless分析/image-20260524042834-5lx42db.png)

0x00000000006B7C34函数

先获取第一个节表的name，这里是text

![image](/img/stageless分析/image-20260524044848-llucg5x.png)

然后获取节表的内存对齐和文件对齐大小，从原始地址+文件偏移处读取sizeofrawdata的数据到新分配的地址空间+内存对齐大小处，这里也就是从72100开始写入

![image](/img/stageless分析/image-20260524045014-tktyjd2.png)

![image](/img/stageless分析/image-20260524045021-mzta5bn.png)

rsp指向节表的头部，一个节表大小是0x28，因此这一行

00000000006B7D10 | 48:83C0 28               | add rax,28                         | 指向下一个text节

直接可以控制指向下一个节表，然后再将文件地址拷贝到虚拟地址里

![image](/img/stageless分析/image-20260524050251-23dpxr4.png)

到此，文件已经完全拷贝到内存空间里并展开了。

## 修复导入表

接着传入四个参数，调用6b7d34。

![image](/img/stageless分析/image-20260524175618-ifd2ibo.png)

首先在文件末尾往前创建一个40字节大小的空间，这个空间主要是用来存储变量。

![image](/img/stageless分析/image-20260524182418-gn3nzva.png)

接着解析pe结果，找到导入表的地址，然后判断第一个IMAGE\_IMPORT\_DESCRIPTOR的name也就是dll名称是否为空，如果不为空就把dll名写到刚刚40空间大小的位置。

![image](/img/stageless分析/image-20260524182618-yixzswb.png)

接着传入以下参数，调用6b7134

![image](/img/stageless分析/image-20260524182707-15essbd.png)

进入6b7134，只做了一个0比较就退出了

![image](/img/stageless分析/image-20260524183116-55xiao8.png)

然后调用自实现的loadlibrary加载kernel32

![image](/img/stageless分析/image-20260524183316-rd9y6qr.png)

接着是一段修复导入表的代码，代码核心思想是通过FirstThunk（IAT 地址表 RVA）来读取当前_IMAGE_IMPORT_DESCRIPTOR结构里面，对应dll的函数名，

然后调用前面动态获取到的getprocaddress来加载对应函数，获取函数的返回地址，直接将其保存在FirstThunk指向的地址中。

简单说就是读函数名从IAT进行，写函数还是写到了IAT里面，INT完全没用到。。

首先加载k32以后，将其地址保存。然后根据前面保存的内容，获取到内存dll中的OriginalFirstThunk 和FirstThunk并储存

![image](/img/stageless分析/image-20260527020508-34crglw.png)

![image](/img/stageless分析/image-20260527020340-tqmwfzd.png)

接着判断这两个值是否为0来做循环结束，但实际上只有IAT为0时候就结束了。

![image](/img/stageless分析/image-20260527020550-fpeulf8.png)

然后跳转至0x00000000006B7F29，先计算IAT的va，然后将IAT中的值读到rsp+20里面。

这里因为iat地址指向的结构是

typedef struct _IMAGE_IMPORT_BY_NAME {  
    WORD Hint;  
    CHAR Name[1];  
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

因此+2才是函数名。

![image](/img/stageless分析/image-20260527020642-1vdkheh.png)

接着先做了一个简单校验，然后就调用getprocaddress来调用函数

![image](/img/stageless分析/image-20260527021024-4bj05aj.png)

然后将获取到的函数保存到当前IAT指向的地址，接着IAT和INT都后移qword个大小，然后返回上述导入k32下一行继续进行修复导入表。

![image](/img/stageless分析/image-20260527021054-5mf7n08.png)

接着指向下一个_IMAGE_IMPORT_DESCRIPTOR结构，该结构大小为20字节，因此对应十六进制的14。

![image](/img/stageless分析/image-20260527022117-gl1f6et.png)

跟上去发现加载下一个dll了

![image](/img/stageless分析/image-20260527022311-bms1467.png)

当解析导入表数组中，dllname为0时跳转到下面的代码

![image](/img/stageless分析/image-20260527022454-ksc418i.png)

主要是用来清除在PE尾部保存的一些函数名

![image](/img/stageless分析/image-20260527022643-o6ksenv.png)

同时保存一个sock函数到rdx里

![image](/img/stageless分析/image-20260527022833-ufajwio.png)

‍

‍

## 修复重定位表

然后接着进入下一个函数6B7FF4

![image](/img/stageless分析/image-20260531023720-5fddukh.png)

首先获取了实际加载地址和Imagebase的差值

![image](/img/stageless分析/image-20260531023813-rkrko9x.png)

接着通过可选目录，获取重定位表的位置，然后判断第一组重定位块的大小是否为0

![image](/img/stageless分析/image-20260531023900-09tugio.png)

然后先获取第一个重定位项要修复的页面基页，然后计算当前重定位块组的数量，有几个重定位项要修复。

接着获取第一个重定位项的地址，然后把之前计算的重定位项的数量减1，判断是否处理完当前重定位项组。

![image](/img/stageless分析/image-20260531024002-dy5d5cg.png)

然后处理当前重定位项，先判断其高四位是否为A，也就是IMAGE_REL_BASED_DIR64，接着修复页。

![image](/img/stageless分析/image-20260531024352-bmzhehj.png)

然后处理下一个块项，直接+2就行

![image](/img/stageless分析/image-20260531024502-kfakj8i.png)

当处理完第一组块时，会跳入到这里。  
因为块是连续存储的，所以第一个块组的首地址+第一个块组的大小，就是第二个块组的首地址。

![image](/img/stageless分析/image-20260531024524-x5p4d6m.png)

接着会继续上述操作，直到修复完所有重定位项。

接着就是通过pNtHeader->OptionalHeader.AddressOfEntryPoint；EntryVA = DllBase + AddressOfEntryPoint;

调用dll。

最后按 DLL 入口函数约定调用它：

​`((DllMain_t)EntryVA)(     DllBase,     DLL_PROCESS_ATTACH,     lpReserved );`

‍
