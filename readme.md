Shodan api
===


## 簡介

[TOC]



## 使用環境


1. ubuntu
2. python2
3. python3(至少目前可以)


前置步驟
---
請先安裝相關檔案

1.
```gherkin=
pip install shodan
```

2.找到自己API並放入shodan2_0.py裡標註地方。


相關疑問或是想看官方範例,可以查看以下連結:
https://github.com/achillean/shodan-python
<br/>

可選功能
---
-h 針對單個主機進行搜尋
<br/>
-s 針對你想搜尋的語法搜尋(Ex:server="apache")
<br/>

使用範例
---

```gherkin=
python2 shodan2_0.py -h test
```

<br/>1.請把搜尋的內容打在test,目前只支持讀取單行。
<br/>
2.test 可隨意更換檔案名稱,並不影響程式執行。
<br/>

## 範例截圖

![](https://i.imgur.com/VIvVQiJ.png)

![](https://i.imgur.com/49iwo9c.png)

![](https://i.imgur.com/8d33ZhU.png)
