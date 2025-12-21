import * as fs from "fs";
import Java from 'frida-java-bridge';
import {WebRequest, SysStreamReader} from "./gameClass";

export function isFileExists(path) {
    try {
        return fs.statSync(path).isFile
    } catch {
        return false
    }
}

export function androidhttpGet(targetUrl: string): Promise<any> {
    return new Promise((resolve, reject) => {
        Java.perform(function () {
            try {
                var HttpURLConnection = Java.use("java.net.HttpURLConnection");
                var URL = Java.use("java.net.URL");
                var BufferedReader = Java.use("java.io.BufferedReader");
                var StringBuilder = Java.use("java.lang.StringBuilder");
                var InputStreamReader = Java.use("java.io.InputStreamReader");

                var url = URL.$new(Java.use("java.lang.String").$new(targetUrl));
                var conn = url.openConnection();
                conn = Java.cast(conn, HttpURLConnection);
                conn.setRequestMethod("GET");
                conn.setConnectTimeout(5000);
                conn.setReadTimeout(5000);
                conn.setDoInput(true);
                conn.setChunkedStreamingMode(0);
                conn.connect();

                var code = conn.getResponseCode();
                var data = null;

                if (code == 200) {
                    var inputStream = conn.getInputStream();
                    var buffer = BufferedReader.$new(InputStreamReader.$new(inputStream));
                    var sb = StringBuilder.$new();
                    var line = null;

                    while ((line = buffer.readLine()) != null) {
                        sb.append(line);
                    }

                    data = sb.toString();
                    data = JSON.parse(data);
                    resolve(data);
                } else {
                    console.error('Failed to get ' + targetUrl + '. http code:', code);
                    reject("error: " + code);
                }

                conn.disconnect();
            } catch (error) {
                reject(error);
            }
        });
    });
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