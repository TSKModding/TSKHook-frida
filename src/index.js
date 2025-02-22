import 'frida-il2cpp-bridge'
import fs from "fs";

function logToAndroid(text) {
    Java.perform(() => {
        let Log = Java.use("android.util.Log");
        let TAG_L = "[tskhook-frida]";
        Log.v(TAG_L, text);
    });
}

(function hijackConsole() {
    let originalLog = console.log;
    let originalError = console.error;

    console.log = function (...args) {
        let message = args.map(arg => {
            if (typeof arg === "object") {
                return JSON.stringify(arg, null, 2);
            }
            return String(arg);
        }).join(" ");

        logToAndroid(message);
        originalLog.apply(console, args);
    };

    console.error = function (...args) {
        let message = args.map(arg => {
            if (typeof arg === "object") {
                return JSON.stringify(arg, null, 2);
            }
            return String(arg);
        }).join(" ");

        logToAndroid(`[ERROR] ${message}`);
        originalError.apply(console, args);
    };
})();

console.log('tsk injector started.');

function isFileExists(path) {
    try {
        return fs.statSync(path).isFile
    } catch {
        return false
    }
}

function getFontPath() {
    const fontName = 'notosanscjktc'
    const filePath = Il2Cpp.application.dataPath + '/il2cpp/' + fontName
    if (isFileExists(filePath)) {
        return filePath
    }
    return ''
}

Il2Cpp.perform(() => {
    const S = s => Il2Cpp.string(s)
    const ASM = asm => Il2Cpp.domain.assembly(asm)
    const str = s => s.toString().replace(/^"|"$/g, '')

    const AssemblyCSharp = ASM('Assembly-CSharp').image

    setupTranslaion()

    function setupTranslaion() {
        const T = {
            names: {},
            chapters: {},
            fontBundle: null,
            font: null,
            tmpFont: null,
            advId: null,
            fontPath: null,
            api: 'https://translation.lolida.best/download/tsk'
        }

        setTimeout(function () {
            T.fontPath = getFontPath()
        }, 5000)

        const AdvPage = AssemblyCSharp.class('Utage.AdvPage')
        const AdvBacklog = AssemblyCSharp.class('Utage.AdvBacklog')
        const UguiNovelText = AssemblyCSharp.class('Utage.UguiNovelText')
        const AdvDataManager = AssemblyCSharp.class('Utage.AdvDataManager')
        const LanguageManagerBase = AssemblyCSharp.class('Utage.LanguageManagerBase')
        const AdventureTitleBandView = AssemblyCSharp.class('Utage.AdventureTitleBandView')

        AdventureTitleBandView.method('Initialize').implementation = function () {
            const TitleText = str(this.method('get_TitleText').invoke())
            if (T.advId in T.chapters && TitleText in T.chapters[T.advId]) {
                this.method('set_TitleText').invoke(S(T.chapters[T.advId][TitleText]))
            }
            this.method('Initialize').invoke()
            if (T.tmpFont !== null) {
                this.field('upTextComp').value.field('text').value.method('set_font').invoke(T.tmpFont)
                this.field('donwTextComp').value.field('text').value.method('set_font').invoke(T.tmpFont)
                const titleText = this.field('titleText').value
                for (let i = 0; i < titleText.length; i++) {
                    titleText.get(i).method('set_font').invoke(T.tmpFont)
                }
                const donwTextObject = this.field('donwTextObject').value
                const TKSTextTMPGUI = AssemblyCSharp.class('TKSTextTMPGUI')
                for (let i = 0; i < donwTextObject.length; i++) {
                    donwTextObject.get(i).method('GetComponent').inflate(TKSTextTMPGUI).invoke().field('text').value.method('set_font').invoke(T.tmpFont)
                }
            }
        }

        AdvDataManager.method('DownloadChaperKeyFileUsed').implementation = function (scenarioLabel) {
            const label = str(scenarioLabel)
            if (!scenarioLabel.isNull() && (T.font === null || T.tmpFont === null)) {
                loadFont()
            }
            T.advId = label.toLowerCase()
            if (!scenarioLabel.isNull()) {
                console.log(T.advId);
            }
            if (!scenarioLabel.isNull() && !(T.advId in T.chapters)) {
                sendHttpRequest(`${T.api}/${T.advId}/zh_Hant/?format=json`, (data) => {
                    T.chapters[T.advId] = JSON.parse(data)
                    console.log('chapter translation loaded. Total:', Object.keys(T.chapters[T.advId]).length);
                })
            }
            if (scenarioLabel.isNull() && Object.keys(T.names).length === 0) {
                sendHttpRequest(`${T.api}/tsk_name/zh_Hant/?format=json`, (data) => {
                    T.names = JSON.parse(data)
                    sendHttpRequest(`${T.api}/tsk_subname/zh_Hant/?format=json`, (data) => {
                        T.names = Object.assign(T.names, JSON.parse(data))
                        console.log('name translation loaded. Total:', Object.keys(T.names).length);
                    })
                })
            }
            this.method('DownloadChaperKeyFileUsed').invoke(...arguments)
        }

        UguiNovelText.method('OnEnable').implementation = function () {
            this.method('OnEnable').invoke()
            if (T.font !== null) {
                this.method('set_font').invoke(T.font)
            }
        }

        AdvBacklog.method('get_MainCharacterNameText').implementation = function () {
            const name = str(this.method('get_MainCharacterNameText').invoke())
            if (name in T.names && T.names[name]) {
                return S(T.names[name])
            }
            return S(name)
        }

        AdvPage.method('get_NameText').implementation = function () {
            const name = str(this.method('get_NameText').invoke())
            if (name in T.names && T.names[name]) {
                return S(T.names[name])
            }
            return S(name)
        }

        LanguageManagerBase.method('ParseCellLocalizedTextBySwapDefaultLanguage').implementation = function () {
            const text = str(this.method('ParseCellLocalizedTextBySwapDefaultLanguage').invoke(...arguments))
            if (T.advId in T.chapters && text in T.chapters[T.advId]) {
                return S(T.chapters[T.advId][text])
            }
            return S(text)
        }

        async function loadFont() {
            try {
                const fontPath = S(T.fontPath)
                const TextMeshPro = ASM('Unity.TextMeshPro').image
                const TextRenderModule = ASM('UnityEngine.TextRenderingModule').image
                const AssetBundleModule = ASM('UnityEngine.AssetBundleModule').image
                const AssetBundle = AssetBundleModule.class('UnityEngine.AssetBundle')

                if (T.fontBundle === null) {
                    T.fontBundle = AssetBundle.method('LoadFromFile').invoke(fontPath)
                }

                if (T.tmpFont === null) {
                    const loadTMPFontRequest = T.fontBundle.method('LoadAssetAsync').inflate(TextMeshPro.class('TMPro.TMP_FontAsset')).invoke(S('notosanscjktc SDF'))
                    while (!loadTMPFontRequest.method('get_isDone').invoke()) {
                        await new Promise(resolve => setTimeout(resolve, 100));
                    }
                    T.tmpFont = loadTMPFontRequest.method('get_asset').invoke()
                }

                if (T.font === null) {
                    const loadFontRequest = T.fontBundle.method('LoadAssetAsync').inflate(TextRenderModule.class('UnityEngine.Font')).invoke(S('notosanscjktc'))
                    while (!loadFontRequest.method('get_isDone').invoke()) {
                        await new Promise(resolve => setTimeout(resolve, 100));
                    }
                    T.font = loadFontRequest.method('get_asset').invoke()
                }

                T.fontBundle.method('Unload').invoke(false)

                if (T.font !== null && T.tmpFont !== null) {
                    console.log("font load succeed.");
                }
            } catch (e) {
                console.error(e)
            }
        }

        async function sendHttpRequest(urlString, callback) {
            let URL = Java.use('java.net.URL');
            let url = URL.$new(urlString);

            let connection = Java.cast(url.openConnection(), Java.use('java.net.HttpURLConnection'));
            connection.setRequestMethod('GET');
            connection.setRequestProperty('Content-Type', 'application/json');
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);
            connection.setDoInput(true);
            connection.setChunkedStreamingMode(0);
            connection.connect();

            let code = connection.getResponseCode();

            if (code === 200) {
                let BufferedReader = Java.use('java.io.BufferedReader');
                let InputStreamReader = Java.use('java.io.InputStreamReader');
                let reader = BufferedReader.$new(InputStreamReader.$new(connection.getInputStream()));
                let inputLine;
                let response = '';
                while ((inputLine = reader.readLine()) !== null) {
                    response += inputLine;
                }
                reader.close();
                callback(response)
            } else {
                console.error('Failed to get ' + urlString + '. http code:', code);
                callback('{}')
            }

            connection.disconnect();
        }
    }
})