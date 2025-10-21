export let config = {
    "transGameNovelCharaNameUrl": "https://translation.lolida.best/download/tsk/tsk_name/zh_Hant/?format=json",
    "transGameNovelCharaSubNameUrl": "https://translation.lolida.best/download/tsk/tsk_subname/zh_Hant/?format=json",
    "transGameNovelChapterUrl": (label) => {
        return `https://translation.lolida.best/download/tsk/${label}/zh_Hant/?format=json`
    },
    "fontName": "notosanscjktc",
}
