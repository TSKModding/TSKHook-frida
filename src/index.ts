import "./gameClass.js";
import "./patch.js";
import {LogClass} from "./gameClass";

function logToAndroid(level, text) {
    LogClass.method(level).invoke(Il2Cpp.string("[tskhook-frida] " + text))
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

        logToAndroid('Log', message);
        originalLog.apply(console, args);
    };

    console.error = function (...args) {
        let message = args.map(arg => {
            if (typeof arg === "object") {
                return JSON.stringify(arg, null, 2);
            }
            return String(arg);
        }).join(" ");

        logToAndroid('LogError', `[ERROR] ${message}`);
        originalError.apply(console, args);
    };
})();
