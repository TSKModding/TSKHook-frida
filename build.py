import glob
import subprocess
import shutil
import os
import requests
import platform
import base64

apkUrl = 'https://dl-app.games.dmm.com/android/jp.co.fanzagames.twinklestarknightsx_a'
app_version = ''
apk_file = ''
fontName = 'notosanscjktc'
is_windows = platform.system() == 'Windows'
build_tools_version = '35.0.0'


def process_apk():
    apk_filename = 'tsk_dmm_' + app_version + '_translation.apk'
    subprocess.run(['apktool', 'd', '-f', '-r', apk_file, '-o', './tsk_r_programdata'], check=True, shell=is_windows)
    shutil.rmtree('./tsk_r_programdata/lib/armeabi-v7a')  # remove unsupported armv7
    shutil.copy('./frida/gadget-android-arm64.so', './tsk_r_programdata/lib/arm64-v8a/libgadget.so')
    shutil.copy('./frida/libgadget.config.so', './tsk_r_programdata/lib/arm64-v8a/libgadget.config.so')
    shutil.copy('./dist/_.js', './tsk_r_programdata/lib/arm64-v8a/libgadget.js.so')

    # smali patch
    res = glob.glob("./tsk_r_programdata/*/com/unity3d/player/UnityPlayerActivity.smali")
    for file_name in res:
        with open(file_name, 'r+', encoding='utf-8') as file:
            text = file.read()
            text = text.replace('invoke-direct {p0}, Landroid/app/Activity;-><init>()V',
                                'invoke-direct {p0}, Landroid/app/Activity;-><init>()V'
                                '\n    const-string v0, "gadget"'
                                '\n    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V')
            file.seek(0)
            file.write(text)
            file.truncate()

    # copy fonts
    if not os.path.exists(f"./res/{fontName}"):
        os.makedirs("./res", exist_ok=True)
        with open(f'./res/{fontName}', 'wb') as f:
            f.write(requests.get(
                f'https://github.com/TSKModding/TSKHook-frida/releases/download/v0.0.1/{fontName}').content)
    shutil.copy(f'./res/{fontName}', f'./tsk_r_programdata/assets/bin/Data/Managed/{fontName}')
    subprocess.run(['apktool', 'b', './tsk_r_programdata', '-f', '-o', './dist/' + apk_filename], check=True,
                   shell=is_windows)
    if not os.getenv("GITHUB_ACTIONS"):
        if not os.path.exists('tsk.keystore'):
            subprocess.run(
                ['keytool', '-genkey', '-noprompt', '-dname',
                 'CN=TSKModding, OU=TSKModding, O=TSKModding, L=TSKModding, S=TSKModding, C=TSKModding', '-v',
                 '-keystore', './tsk.keystore', '-alias', 'tsk', '-keyalg', 'RSA', '-keysize',
                 '4096', '-validity', '10000', '-storepass', '123456'], check=True, shell=is_windows)
        subprocess.run(
            ['apksigner', 'sign', '--ks', 'tsk.keystore', '--ks-pass', 'pass:123456', './dist/' + apk_filename],
            check=True, shell=is_windows)
    else:
        keystore = os.getenv("KEYSTORE")
        with open('tsk.keystore', 'wb') as f:
            f.write(base64.b64decode(keystore))
        subprocess.run(
            [f"{os.getenv('ANDROID_HOME')}/build-tools/{build_tools_version}/apksigner", 'sign', '--ks',
             'tsk.keystore', '--ks-pass', 'pass:123456', './dist/' + apk_filename], check=True)


def get_version():
    content = requests.get(url='https://api.store.games.dmm.com/freeapp/705566')
    data = content.json()
    return data['free_appinfo']['app_version_name']


def download_apk():
    global app_version, apk_file
    app_version = get_version()
    apk_file = f'./apk/{app_version}.apk'
    if not os.path.exists(f"./apk"):
        os.makedirs(f"./apk")
    if not os.path.exists(apk_file):
        response = requests.get(apkUrl)
        with open(apk_file, 'wb') as f:
            f.write(response.content)
        return True
    return False


def main():
    is_downloaded = download_apk()
    if is_downloaded:
        print('downloaded')
    else:
        print('already downloaded')
    subprocess.run(['npm', 'run', 'build'], check=True, shell=is_windows)
    process_apk()


if __name__ == '__main__':
    main()
