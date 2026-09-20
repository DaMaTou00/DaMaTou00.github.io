# 一个小糖人

基于 Hexo + Fluid 主题的个人博客，部署在 GitHub Pages。

## 本地预览

```bash
npm install        # 首次运行需要，安装依赖
npm run server     # 启动本地预览
```

浏览器打开 http://localhost:4000 查看效果，改完文件保存会自动刷新。按 `Ctrl+C` 停止。

## 写一篇新文章

```bash
npx hexo new "文章标题"
```

会在 `source/_posts/` 生成一个 Markdown 文件，编辑它就行：

```markdown
---
title: 文章标题
date: 2026-09-20 22:40:00
tags:
  - 标签
categories:
  - 分类
---

正文用 Markdown 写。
```

常用语法：`##` 二级标题、`**加粗**`、`- ` 列表、三个反引号包代码块、`![](图片链接)` 插图。

写完后推送到 GitHub 即可，剩下的自动完成：

```bash
git add .
git commit -m "new post: 文章标题"
git push
```

## 首次部署到 GitHub（重要）

### 1. 创建仓库

在 GitHub 新建仓库，名字**必须**是：

```
DaMaTou00.github.io
```

可见性选 **Public**，不要勾选 README / .gitignore / license。

### 2. 关联并推送

```bash
git remote add origin https://github.com/DaMaTou00/DaMaTou00.github.io.git
git branch -M main
git push -u origin main
```

### 3. 打开 GitHub Pages

进入仓库 **Settings → Pages**，把 **Source** 选成 **GitHub Actions**（不是 Deploy from a branch）。

### 4. 等待部署

去仓库的 **Actions** 标签页看进度，绿色的勾表示成功。约 1–2 分钟后访问：

```
https://DaMaTou00.github.io
```

如果 Actions 报权限错误，检查 Settings → Actions → General → Workflow permissions 是否勾选了 **Read and write permissions**。

## 常见修改位置

| 想改什么 | 改哪个文件 |
| --- | --- |
| 博客标题、作者、网址 | `_config.yml` |
| 导航栏菜单、配色、页脚 | `_config.fluid.yml` |
| 关于页内容 | `source/about/index.md` |
| 文章 | `source/_posts/` |
| 图片 | 放 `source/img/`，文章里写 `/img/文件名` |

改完主题配置记得清一次缓存再预览：

```bash
npm run clean && npm run server
```

## 目录结构

```
blog/
├── _config.yml            # 站点配置
├── _config.fluid.yml      # 主题配置
├── package.json
├── scaffolds/             # 新建文章的模板
├── source/
│   ├── _posts/            # 文章都在这里
│   └── about/             # 关于页
└── .github/workflows/
    └── deploy.yml         # 自动部署脚本
```

## 备注

- `node_modules/` 和 `public/` 已被 `.gitignore` 忽略，不会推到仓库。
- 主题安装在 `node_modules/hexo-theme-fluid`，升级用 `npm update hexo-theme-fluid`。
- 想绑自定义域名：在 `source/` 下新建 `CNAME` 文件（内容写一行域名），DNS 加 CNAME 记录指向 `DaMaTou00.github.io`，再在 Settings → Pages 里填上域名并勾选 Enforce HTTPS。
