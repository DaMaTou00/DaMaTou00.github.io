---
title: pan-baidu
date: 2026-09-21 00:25:00 +08:00
tags:
  - 样本分析
  - 钓鱼木马
categories:
  - 木马分析
---

# pan-baidu

## 钓鱼网站

伪造网站**pan-baidu.com**

![image](/img/pan-baidu/image-20260716215526-ur6gn5j.png)

下载并解压，有一个单文件

![image](/img/pan-baidu/image-20260716215611-m68c1vz.png)

## 基础信息分析

文件使用C语言编写，程序为32位，其中rsrc存在高熵值特征。压缩包大小约90MB，此举动是为了使用大文件绕过文件扫描且文件类型识别为 NSIS安装器。

![image](/img/pan-baidu/image-20260716215746-63iyb7p.png)

## 动态运行

![image](/img/pan-baidu/image-20260716220406-4fyau8l.png)

使用火绒剑监控，执行该程序，看看其做了哪些动作：

1、检测杀软

![image](/img/pan-baidu/image-20260719202236-nalsgka.png)

2、设置defender扫描白名单

![image](/img/pan-baidu/image-20260719202407-0naf169.png)

3、创建文件

在排除C:\Users\offer\AppData\Local\Temp这一临时目录（这个目录下操作的文件结束后已删除），主要定位到程序在  
C:\Users\offer\AppData\Roaming创建了非常多的文件。具体如下。

![image](/img/pan-baidu/image-20260719201958-1mzxh47.png)

![image](/img/pan-baidu/image-20260719201710-e8y3m6l.png)

C2外联：

![image](/img/pan-baidu/image-20260719204813-dresp78.png)

由于日志较多，这里可以运行结束以后，交给AI做辅助研判，这里因为火绒剑一次可导出的日志量较少，因此需要在过滤器里面过滤好动作， 重点看文件创建，进程创建执行，注册表修改相关。

用cc总结一下大致如下

![image](/img/pan-baidu/image-20260719203814-xdwonpk.png)

## 静态分析

C:\Users\offer\AppData\Roaming\目录下，存在两个创建的目录，两个目录下的同名exe为实际的loader加载器，这里重点去分析这两个。

![image](/img/pan-baidu/image-20260719205128-t4ai9is.png)

一个32位的exe

![image](/img/pan-baidu/image-20260802163323-xjpbtjx.png)

#### ev2c34.exe

程序的资源节和版本信息都和MicrosoftEdgeUpdate.exe十分相似，对比主函数发现是大致一样的，并且查看其他函数发现和MicrosoftEdgeUpdate.exe逻辑十分相似，初步判断采用了patch手法进行代码修改。

恶意程序

![image](/img/pan-baidu/image-20260719214228-co57zs0.png)

正常程序

![image](/img/pan-baidu/image-20260719214239-fwa1nza.png)

如果使用patch写loader，那么不可避免的会使用peb进行dll的获取，因此可根据这个特征来定位具体代码

**这里使用辅助工具capa：https://github.com/mandiant/capa**

使用capa <target> -vv 获取详细信息，**并**把结果吐给cc进行辅助分析（比直接用mcp分析省token）

![image](/img/pan-baidu/image-20260719233934-kika23s.png)

##### sub_419072

很经典的从peb找到kernel32.dll的动作。

![image](/img/pan-baidu/image-20260719235037-i2eqd2h.png)

通过hash比对获取一些win32的函数，通过分析解密方式，获取的函数换源大致如下

┌────────────┬────────────────────┐  
  │    Hash    │        API         │  
  ├────────────┼────────────────────┤  
  │ 51029213   │ LoadLibraryA       │  
  ├────────────┼────────────────────┤  
  │ 52968519   │ VirtualAlloc       │  
  ├────────────┼────────────────────┤  
  │ 1982987661 │ GetModuleFileNameA │  
  ├────────────┼────────────────────┤  
  │ 16582688   │ CreateFileA        │  
  ├────────────┼────────────────────┤  
  │ 16598042   │ GetFileSize        │  
  ├────────────┼────────────────────┤  
  │ 635627     │ ReadFile           │  
  └────────────┴────────────────────┘

这里动态调试验证一下，其中需要根据RVA计算一下这个函数在动态加载时候的va，本次测试时候va是004B8F54

第一次函数运行返回

![image](/img/pan-baidu/image-20260802163817-bb6fw4p.png)

第二次

![image](/img/pan-baidu/image-20260802164013-e51unen.png)

第三次

![image](/img/pan-baidu/image-20260802164026-mpzdh8v.png)

第四次

![image](/img/pan-baidu/image-20260802164038-ddw5tqa.png)

第五次

![image](/img/pan-baidu/image-20260802164127-1fbqftt.png)

第六次

![image](/img/pan-baidu/image-20260802164139-fbazgsr.png)

这里通过解密字符串获取了user32的dll名称，并按照上述方式获取messagebox函数

![image](/img/pan-baidu/image-20260802162836-u75krfv.png)

![image](/img/pan-baidu/image-20260802164308-s1orbn6.png)

##### sub_418F54

这里紧跟着419072，且函数传递结构为上一步骤获取的K32的dll base和一个密文，一个非常标准的从dll中获取导出函数的动作。

![image](/img/pan-baidu/image-20260802162204-468nkk2.png)

##### sub_418DCD

这里先通过GetModuleFileNameA函数获取到当前loader的一个文件路径信息

![image](/img/pan-baidu/image-20260802181150-jcysj7k.png)

![image](/img/pan-baidu/image-20260802213729-050gt6n.png)

紧接着，他会处理路径，把路径最后的exe替换成fhkan.io，并调用Creatfile打开文件，并调用GetFileSize获取文件的大小，创建一块内存空间，通过readfile把shellcode读进去，然后通过异或36进行解密。最后执行shellcode。

![image](/img/pan-baidu/image-20260802181220-c9qbsfo.png)

![image](/img/pan-baidu/image-20260802214042-ddve1b6.png)

![image](/img/pan-baidu/image-20260802214716-0m4gf25.png)

![image](/img/pan-baidu/image-20260802214742-sq5j5zm.png)

![image](/img/pan-baidu/image-20260802214851-l3sfv34.png)

提取出来shellcode做进一步分析。

savadata  文件地址,起始地址,大小

整个调用关系

![image](/img/pan-baidu/image-20260802231751-wdugmgl.png)

#### shellcode

shellcode内嵌了一个dll，DIE可以扫描出来。

![image](/img/pan-baidu/image-20260802225309-mrwpvp8.png)

定位shellcode要么搜索PE头要么MZ。

![image](/img/pan-baidu/image-20260802225253-i8u0xet.png)

根据DIE分析的导出这个DLL，导出只有一个函数，导入表没有网络请求相关的。

![image](/img/pan-baidu/image-20260802231007-89zd9ju.png)

![image](/img/pan-baidu/image-20260802231019-8hvdvy7.png)

后续补充对于该dll的内容分析
