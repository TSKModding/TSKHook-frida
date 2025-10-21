import {config} from './config.js';
import * as util from './util.js';
export let chapterDicts: Record<string, Record<string, string>> = {};
export let nameDicts: Record<string, string> = {};


export async function Init() {
    const url1 = config.transGameNovelCharaNameUrl;
    nameDicts = await util.androidhttpGet(url1);
    const url2 = config.transGameNovelCharaSubNameUrl;
    let respData = await util.androidhttpGet(url2);
    Object.assign(nameDicts, respData);

    console.log('name translation loaded. Total:', Object.keys(nameDicts).length);
}

export async function FetchChapterTranslation(label) {
    const url = config.transGameNovelChapterUrl(label);
    chapterDicts[label] = await util.androidhttpGet(url);

    console.log('chapter translation loaded. Total:', Object.keys(chapterDicts[label]).length);
}
