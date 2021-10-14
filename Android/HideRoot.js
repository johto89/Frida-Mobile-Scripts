var FridaRootPath = new Array(
    "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su", "/data/local/xbin/su",
    "/data/local/bin/su", "/system/sd/xbin/su", "/system/bin/failsafe/su", "/data/local/su", "/su/bin/su",
    "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su", "/sbin/su", "/su/bin/su", "/system/bin/su",
    "/system/bin/.ext/su", "/system/bin/failsafe/su", "/system/sd/xbin/su", "/system/usr/we-need-root/su",
    "/system/xbin/su", "/cache/su", "/data/su", "/dev/su", "/data/local/tmp/re.frida.server", "/data/local/tmp/frida-server",
    "com.noshufou.android.su", "com.noshufou.android.su.elite", "eu.chainfire.supersu", "com.koushikdutta.superuser",
    "com.thirdparty.superuser", "com.yellowes.su", "com.koushikdutta.rommanager",
    "com.koushikdutta.rommanager.license", "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
    "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro", "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
    "de.robv.android.xposed.installer", "com.saurik.substrate", "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot",
    "com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium", "com.formyhm.hideroot", "me.phh.superuser",
    "eu.chainfire.supersu.pro", "com.kingouser.com", "cc.madkite.freedom", "com.android.vending.billing.InAppBillingService.COIN", "com.topjohnwu.magisk",
    "/sbin/.magisk/", "/sbin/magiskpolicy", "/sbin/magiskhide", "/sbin/.core/mirror", "/sbin/.core/img", "/sbin/.core/db-0/magisk.db",
    "/sbin/magiskinit", "/dev/.magisk.unblock", "/sbin/magisk", "/data/adb/magisk.img", "/data/adb/magisk.db", "/data/adb/.boot_count",
    "/data/adb/magisk_simple", "/cache/.disable_magisk", "/cache/magisk.log", "/init.magisk.rc", "/data/adb/riru/api_version", "/data/adb/riru/bin/rirud", "/data/adb/edxp/misc_path"
);

var Executable = ["sh", "getprop", "which", "mount", "build.prop", "id", "su"];

var ExeHook = ["execl", "execle", "execlpe", "execlp", "execv", "execve", "execvp", "execvpe"];
ExeHook.forEach(function LibcHooks(methodName) {
    try {
        var modulePtr = Module.findExportByName("libc.so", methodName);
        Interceptor.attach(modulePtr, {
            onEnter: function(args) {
                this.value = false;
                var cmd = Memory.readCString(args[0]);
                var Hide = (Executable.indexOf(cmd) > -1);
                if (Hide) {
                    console.log("libc.so ! Exec* : " + methodName + " => " + cmd + "\n");
                    var NewCommand = args[0].writeUtf8String("HaHaHaHaHaHa");
                    args[0] = ptr(NewCommand);
                    this.value = true;
                }
            },
            onLeave: function(retval) {
                if (this.value) {
                    retval.replace(-1);
                }
            }
        });
    } catch (ex) {
        // console.log("Method ", methodName, " not found for hooking, skipping hook.");
    }
});

var NormalExportHook = ["open", "fopen", "access", "stat", "system", "readlink", "sprintf", "sscanf"];
NormalExportHook.forEach(function LibcHooks(Exports) {
    try {
        var modulePtr = Module.findExportByName("libc.so", Exports);
        Interceptor.attach(modulePtr, {
            onEnter: function(args) {
                this.value = false;
                var cmd = Memory.readCString(args[0]);
                var Hide = (FridaRootPath.indexOf(cmd) > -1);
                if (Hide) {
                    console.log("libc.so : " + Exports + " => " + cmd);
                    var NewPath = args[0].writeUtf8String("grep");
                    args[0] = ptr(NewPath);
                    this.value = true;
                }


            },
            onLeave: function(retval) {
                if (this.value) {
                    retval.replace(-1);
                }
            }
        });
    } catch (ex) {
        console.error(ex);
        // console.log("Method ", methodName, " not found for hooking, skipping hook.");
    }
});
//readlinkat
var NormalExportHook2 = ["faccessat", "readlinkat"];
NormalExportHook2.forEach(function LibcHooks(ExportsName) {
    try {
        var modulePtr = Module.findExportByName("libc.so", ExportsName);
        Interceptor.attach(modulePtr, {
            onEnter: function(args) {
                this.value = false;
                var cmd = Memory.readCString(args[1]);
                var Hide = (FridaRootPath.indexOf(cmd) > -1);
                if (Hide) {
                    console.log("libc.so : " + ExportsName + " => " + cmd);
                    var NewPath = args[1].writeUtf8String("/we/dont/exist");
                    args[1] = ptr(NewPath);
                    this.value = true;
                }

            },
            onLeave: function(retval) {
                if (this.value) {
                    retval.replace(-1);
                }
            }
        });
    } catch (ex) {
        // console.log("Method ", methodName, " not found for hooking, skipping hook.");
    }
});

Java.perform(function() {
    var PackageManager = Java.use("android.app.ApplicationPackageManager");
    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pkgname, flags) {
        var Hide = (FridaRootPath.indexOf(pkgname) > -1);
        if (Hide) {
            console.log("Bypass Package: " + pkgname);
            var newpkgname = "this.is.funny.package.name";
            return this.getPackageInfo.call(this, newpkgname, flags);
        }
        return this.getPackageInfo.call(this, pkgname, flags);
    }
})