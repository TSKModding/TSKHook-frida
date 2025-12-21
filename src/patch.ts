import * as gameClass from "./gameClass.js";
import * as Translation from "./translation.js";
import {config} from "./config.js"
import {isFileExists} from "./util.js";

export let fontBundle: Il2Cpp.Object;
export let tmpFont: Il2Cpp.Object;
export let assetFont: Il2Cpp.Object;

setTimeout(Translation.Init, 5000); //for frida-gadget,some functions need to wait.

let fontPath: string;

setTimeout(() => {
    fontPath = `${Il2Cpp.application.dataPath}/il2cpp/${config.fontName}` // ".dataPath" need to wait in frida-server spawn mode. upstream bug?
}, 5000);

let currentAdvId;

const toStr = s => s.toString().replace(/^"|"$/g, '')

Il2Cpp.perform(() => {
    gameClass.AdvDataManager.method('DownloadChaperKeyFileUsed').implementation = function (scenarioLabel: Il2Cpp.String) {
        const label = scenarioLabel.content
        if (label != '') {
            if (!tmpFont || !assetFont) {
                loadFont()
            }
            currentAdvId = label.toLowerCase()
            console.log(currentAdvId)

            Translation.FetchChapterTranslation(currentAdvId).then(() => {
                this.method('DownloadChaperKeyFileUsed').invoke(scenarioLabel)
            });
        }
    }
})

async function loadFont() {
    if (isFileExists(fontPath)) {
        if (!fontBundle) {
            let ab = gameClass.AssetBundle.method<Il2Cpp.Object>("LoadFromFile").invoke(Il2Cpp.string(fontPath));
            if (ab.isNull()) {
                console.error("[LoadFromFile] font load failed.");
                tmpFont = null;
            }
            fontBundle = ab;
        }

        if (!tmpFont) {
            const loadTMPFontRequest = fontBundle.method<Il2Cpp.Object>('LoadAssetAsync').inflate(gameClass.TMP_FontAsset).invoke(Il2Cpp.string(config.fontName + " SDF"))
            while (!loadTMPFontRequest.method('get_isDone').invoke()) {
                await new Promise(resolve => setTimeout(resolve, 100));
            }
            tmpFont = loadTMPFontRequest.method<Il2Cpp.Object>('get_asset').invoke()
        }

        if (!assetFont) {
            const loadFontRequest = fontBundle.method<Il2Cpp.Object>('LoadAssetAsync').inflate(gameClass.FontAsset).invoke(Il2Cpp.string(config.fontName))
            while (!loadFontRequest.method('get_isDone').invoke()) {
                await new Promise(resolve => setTimeout(resolve, 100));
            }
            assetFont = loadFontRequest.method<Il2Cpp.Object>('get_asset').invoke()
        }

        fontBundle.method("Unload").invoke(false);

        if (tmpFont && assetFont) {
            console.log("font load succeed.");
        } else {
            console.log("font load failed.");
        }
    } else {
        console.error("font not found");
    }
}

Il2Cpp.perform(() => {
    gameClass.AdventureTitleBandView.method('Initialize').implementation = function () {
        const TitleText = toStr(this.method('get_TitleText').invoke())
        if (tmpFont != null && currentAdvId in Translation.chapterDicts && TitleText in Translation.chapterDicts[currentAdvId]) {
            this.method('set_TitleText').invoke(Il2Cpp.string(Translation.chapterDicts[currentAdvId][TitleText]))
        }
        this.method('Initialize').invoke()
        if (tmpFont != null) {
            this.field<Il2Cpp.Object>('upTextComp').value.field<Il2Cpp.Object>('text').value.method('set_font').invoke(tmpFont)
            this.field<Il2Cpp.Object>('donwTextComp').value.field<Il2Cpp.Object>('text').value.method('set_font').invoke(tmpFont)
            for (const value of this.field<Il2Cpp.Array<Il2Cpp.Object>>('titleText').value) {
                value.method('set_font').invoke(tmpFont)
            }
            const TKSTextTMPGUI = gameClass.Csharp.class('TKSTextTMPGUI')
            for (const value of this.field<Il2Cpp.Array<Il2Cpp.Object>>('donwTextObject').value) {
                value.method<Il2Cpp.Object>('GetComponent').inflate(TKSTextTMPGUI).invoke().field<Il2Cpp.Object>('text').value.method('set_font').invoke(tmpFont);
            }
        }
    }
})

Il2Cpp.perform(() => {
    gameClass.UguiNovelText.method('OnEnable').implementation = function () {
        this.method('OnEnable').invoke()
        if (assetFont != null) {
            this.method('set_font').invoke(assetFont)
        }
    }
})

Il2Cpp.perform(() => {
    gameClass.AdvBacklog.method('get_MainCharacterNameText').implementation = function () {
        const name = toStr(this.method('get_MainCharacterNameText').invoke())
        if (assetFont != null && Translation.nameDicts[name]) {
            return Il2Cpp.string(Translation.nameDicts[name])
        }
        return Il2Cpp.string(name)
    }
})

Il2Cpp.perform(() => {
    gameClass.AdvPage.method('get_NameText').implementation = function () {
        const name = toStr(this.method('get_NameText').invoke())
        if (assetFont != null && Translation.nameDicts[name]) {
            return Il2Cpp.string(Translation.nameDicts[name])
        }
        return Il2Cpp.string(name)
    }
})

Il2Cpp.perform(() => {
    gameClass.LanguageManagerBase.method('ParseCellLocalizedTextBySwapDefaultLanguage').implementation = function () {
        const text = toStr(this.method('ParseCellLocalizedTextBySwapDefaultLanguage').invoke(...arguments))
        if (assetFont != null && currentAdvId in Translation.chapterDicts && text in Translation.chapterDicts[currentAdvId]) {
            return Il2Cpp.string(Translation.chapterDicts[currentAdvId][text])
        }
        return Il2Cpp.string(text)
    }
})
