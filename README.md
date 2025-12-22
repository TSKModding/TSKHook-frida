# TSKHook-frida

### 利用Frida實裝[TSKHook](https://github.com/TSKModding/TSKHook)的翻譯功能
### 只適用於Android 64bit裝置 (請注意: 不支援模擬器)

## 下載

[Releases](https://github.com/TSKModding/TSKHook-frida/releases)

請先移除官方DMM版本，再安裝此版本即可使用。

### *注意*

### **目前有3個不同版本**

#### 第一個為主要版本，檔名只帶有`translation`

使用frida 17編譯而成，針對Android的新版ART變動 (Android>=12)

理論上，小於Android 12的裝置都能使用，除非廠商魔改過系統而導致無法使用，例如：小米?

#### 第二個帶有v16的版本

使用frida 16編譯而成，舊裝置理論上沒有問題，較新的Android可能會無法使用

**如果你是使用Android 14以下的裝置，可以先嘗試第二個版本能不能開啟**

**目前只能用第二個版本的用戶：**

[Android ART](https://source.android.com/docs/core/ota/modular-system/art?hl=zh-tw)是由Google透過Play Store或者廠商透過每月安全性更新推送到用戶裝置上，所以每部裝置都有可能不同

你可能在某天突然用不到第二個版本，這是因為新版ART導致

這時候只能轉用上面或者下面的版本

#### 第三個帶有v17_workaround的版本

這是主要版本的替代版，同樣使用frida 17編譯而成

由於最近ART變動，導致Frida Java API無法正常運作，令到翻譯檔無法載入 (大家都在等待好心人發PR修復)

**如果你只能使用v17，在最近一次的系統更新(2025年11/12月安全性更新)**

**或者Play Store更新後，無法載入翻譯，請嘗試這個版本APK**

適用於裝置的ART版本大於`3611xxxxx`時使用，雖然小於這個版本也可行

**但由於該版本沒有經過大規模測試，所以目前無法確定該版本的穩定性，暫不更換為主要版本**

你可以使用以下 adb 指令查看裝置當前的ART版本，adb使用方法請自行Google

`adb shell pm dump com.google.android.art | findstr version`

當三者皆無法使用時，請到[Discord群](https://discord.gg/XAgHS4zAAk)回報，總之切勿抱有期望，只能說愛莫能助。

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
