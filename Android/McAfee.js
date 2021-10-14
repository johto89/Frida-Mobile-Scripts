/* Bypass Anti Tamper in McAfee Security Version 5.13.0.136 (51300136) */
Java.perform(function() {
    /* Get Original Signature First , Run it on Original Apk and Copy Those Signature
    and use it afterwards as OriginalSign 
    */
    var SignArray = [];
    var Signatures;
    var BuildVersion = Java.use("android.os.Build$VERSION");
    var PackageManager = Java.use("android.content.pm.PackageManager");
    var Context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
    Signatures = 28 <= BuildVersion.SDK_INT.value ? Context.getPackageManager().getPackageInfo(Context.getPackageName(), PackageManager.GET_SIGNING_CERTIFICATES.value).signingInfo.value.getApkContentsSigners() : Context.getPackageManager().getPackageInfo(Context.getPackageName(), PackageManager.GET_SIGNATURES.value).signatures.value;
    for (var iterate = 0; iterate < Signatures.length; iterate += 1) {
        SignArray.push(Signatures[iterate].toCharsString())
    }
    console.log("Original Signature : ", SignArray);
    
    var OriginalSign = "308202b730820220a00302010202044a3f3778300d06092a864886f70d010105050030819e310b3009060355040613025347311230100603550408130953696e6761706f7265311230100603550407130953696e6761706f726531193017060355040a131074656e4375626520507465204c74642e3131302f060355040b13284469676974616c20494420436c6173732033202d204a617661204f626a656374205369676e696e67311930170603550403131074656e4375626520507465204c74642e3020170d3039303632323037343931325a180f32323833303430373037343931325a30819e310b3009060355040613025347311230100603550408130953696e6761706f7265311230100603550407130953696e6761706f726531193017060355040a131074656e4375626520507465204c74642e3131302f060355040b13284469676974616c20494420436c6173732033202d204a617661204f626a656374205369676e696e67311930170603550403131074656e4375626520507465204c74642e30819f300d06092a864886f70d010101050003818d003081890281810088fe995718bb255fa5bd361a8541bb4b10bd24a732a4d2b63b5919ce345f20a0341a2ce7a5619f1114986afe9a8f1e3e3295b0763227523b7323fa722cee8e99d25663169605ebb85f44b18e87c003647dfb9fa13086be12f32d5a0ff9b15552ecac7a185cf2ab8885f0f1c6d285964d460e25fa7a14d761318011e11a6c8b930203010001300d06092a864886f70d01010505000381810052e41884cbef13eefbe35af21cb8415ae63df376d9c87d522d10bcc04599d6c04ac28f9a20bd510f8d7811d56795341b6f191eaef8efa5d37963429ab1d30133e37bfd0e5ddfbb7c47578f4b9191117f267b6124a154748be1da1cce0a728610cc52e1d35171ab1f0350972331b47561085ebd8b405ef649587220cf1525b43e";
    var PMS = Java.use('android.content.pm.Signature')
    PMS["toByteArray"].overload().implementation = function() {
        var output = this["toByteArray"]();
        output = Java.array('byte', hexToBytes(OriginalSign));
        return output;
    };

    function hexToBytes(hex) {
        for (var bytes = [], c = 0; c < hex.length; c += 2)
            bytes.push(parseInt(hex.substr(c, 2), 16));
        return bytes;
    }
    
    var Verf = Java.use("java.security.Signature");
    Verf.verify.overload("[B").implementation = function(by) {
        return true;
    }
    Verf.verify.overload("[B", "int", "int").implementation = function(by, flag, flag2) {
        return true;
    }


})