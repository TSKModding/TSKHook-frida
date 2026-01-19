import * as fs from "fs";
import {WebRequest, SysStreamReader} from "./gameClass";

export function isFileExists(path) {
    try {
        return fs.statSync(path).isFile
    } catch {
        return false
    }
}

export function netHttpGet(targetUrl: string): Promise<any> {
    return new Promise((resolve, reject) => {
        try {
            const request = WebRequest.method<Il2Cpp.Object>('Create').overload('System.String').invoke(Il2Cpp.string(targetUrl));
            const response = request.method<Il2Cpp.Object>('GetResponse').invoke();
            const respStream = response.method<Il2Cpp.Object>('GetResponseStream').invoke();
            const reader = SysStreamReader.new()
            reader.method<Il2Cpp.Object>(".ctor").overload('System.IO.Stream').invoke(respStream);
            const text = reader.method<Il2Cpp.Object>('ReadToEnd').invoke();
            let data = text.toString().replace(/^"|"$/g, '');
            data = JSON.parse(data);
            resolve(data)
        } catch (e) {
            console.error('Failed to get ' + targetUrl + '. Error: ' + e.toString());
            reject(e);
        }

        reject('Failed to get ' + targetUrl);
    });
}