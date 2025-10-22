import "./gameClass.js";
import "./patch.js";

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