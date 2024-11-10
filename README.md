# TSKHook-frida

### 利用Frida實裝[TSKHook](https://github.com/TSKModding/TSKHook)的翻譯功能
### 只適用於Android 64bit裝置

## 下載

[Releases](https://github.com/TSKModding/TSKHook-frida/releases)

請先移除官方DMM版本，再安裝此版本即可使用。

## 編譯

#### 前置需求  
```
Java  
Apktool  
Python  
Node  
Frida-gadget (放入frida/gadget-android-arm64.so)  
Android SDK Build Tools (需要在$PATH中)
```

```shell
npm i
pip install -r requirements.txt
python build.py
```
