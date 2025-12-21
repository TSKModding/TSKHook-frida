import "frida-il2cpp-bridge";

export let Csharp: Il2Cpp.Image;
export let AssetBundleModule: Il2Cpp.Image;
export let TextMeshPro: Il2Cpp.Image;
export let UnityCoreModule: Il2Cpp.Image;
export let TextRenderingModule: Il2Cpp.Image;
export let SystemModule: Il2Cpp.Image;

export let AssetBundle: Il2Cpp.Class;
export let TMP_FontAsset: Il2Cpp.Class;
export let FontAsset: Il2Cpp.Class;
export let SysByte: Il2Cpp.Class;
export let SysFile: Il2Cpp.Class;
export let SysBinaryReader: Il2Cpp.Class;
export let SysClass: Il2Cpp.Class;
export let SysReader: Il2Cpp.Class;

export let AdvPage: Il2Cpp.Class;
export let AdvBacklog: Il2Cpp.Class;
export let UguiNovelText: Il2Cpp.Class;
export let AdvDataManager: Il2Cpp.Class;
export let LanguageManagerBase: Il2Cpp.Class;
export let AdventureTitleBandView: Il2Cpp.Class;

Il2Cpp.perform(() => {
    Csharp = Il2Cpp.domain.assembly("Assembly-CSharp").image;
    AssetBundleModule = Il2Cpp.domain.assembly("UnityEngine.AssetBundleModule").image;
    TextMeshPro = Il2Cpp.domain.assembly("Unity.TextMeshPro").image;
    UnityCoreModule = Il2Cpp.domain.assembly("UnityEngine.CoreModule").image;
    TextRenderingModule = Il2Cpp.domain.assembly('UnityEngine.TextRenderingModule').image;

    SysFile = Il2Cpp.corlib.class("System.IO.File");
    SysByte = Il2Cpp.corlib.class("System.Byte");
    SysBinaryReader = Il2Cpp.corlib.class("System.IO.BinaryReader");
    AssetBundle = AssetBundleModule.class("UnityEngine.AssetBundle");
    TMP_FontAsset = TextMeshPro.class("TMPro.TMP_FontAsset");
    FontAsset = TextRenderingModule.class('UnityEngine.Font');

    AdvPage = Csharp.class('Utage.AdvPage')
    AdvBacklog = Csharp.class('Utage.AdvBacklog')
    UguiNovelText = Csharp.class('Utage.UguiNovelText')
    AdvDataManager = Csharp.class('Utage.AdvDataManager')
    LanguageManagerBase = Csharp.class('Utage.LanguageManagerBase')
    AdventureTitleBandView = Csharp.class('Utage.AdventureTitleBandView')

    SystemModule = Il2Cpp.domain.assembly("System").image;
    SysClass = SystemModule.class('System.Net.WebRequest')
    SysReader = Il2Cpp.corlib.class("System.IO.StreamReader");
});
