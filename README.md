# TSKHook-frida

### 利用Frida實裝[TSKHook](https://github.com/TSKModding/TSKHook)的翻譯功能
### 只適用於Android 64bit裝置 (請注意: 不支援模擬器)

## 下載

[Releases](https://github.com/TSKModding/TSKHook-frida/releases)

請先移除官方DMM版本，再安裝此版本即可使用。

### *注意*

如果第一個APK沒有劇情翻譯，請嘗試第二個檔名帶有v16的APK

第一個使用frida 17編譯而成，針對Android的新版ART變動 (Android>=12)

第二個使用frida 16編譯而成，舊裝置理論上沒有問題，較新的Android可能會無法使用

如果你是使用Android 14以下的裝置，可以先嘗試第二個版本能不能開啟

當兩者皆無法使用時，請到[Discord群](https://discord.gg/XAgHS4zAAk)回報。

## 編譯

#### 前置需求  
```
Java
Apktool
Python
Node
Frida-gadget (放進frida/gadget-android-arm64.so)
Android SDK Build Tools (需要在$PATH中)
```

```shell
npm i
pip install -r requirements.txt
python build.py
```
