
 Java.perform(function () {

/* ################################################################################# */
      /* VPN Detection Bypass  Line 6-85 */
      var NInterface = Java.use("java.net.NetworkInterface");      
      try
       {      
           NInterface.isUp.overload().implementation = function ()
           {  
              console.log("Network Down");      
              return false;
            } 
        }
       catch(err) { console.error(err); } 
       try
        {
            NInterface.getName.overload().implementation = function ()
             {  
                 var IName= this.getName();
                // console.error("InterFace Name : ", IName);
                 if(IName=="tun0" || IName=="ppp0" || IName=="p2p0" || IName =="ccmni0" || IName=="tun")
                  {
                      console.log("Detected Interface Name : ",JSON.stringify(this.getName()));
                      return "FuckYou";
                   }
                return this.getName();
              } 
         }
      catch(err) { console.error(err);  }
      try
       {        
            NInterface.getInterfaceAddresses.overload().implementation = function ()
            {
                var USize = Java.use("java.util.List");
                USize.size.implementation = function ()
                 {
                    console.log("No Interface Installed ");
                    return 0; 
                  }
               return this.getInterfaceAddresses();     
             }
        }
       catch(err) { console.error(err); } 
       try
         {
             var GetProperty = Java.use("java.lang.System");
             GetProperty.getProperty.overload("java.lang.String").implementation = function (getprop)
             {
                if(getprop.indexOf("http.proxyHost")>=0 || getprop.indexOf("http.proxyPort")>=0)
                 { 
                  console.log("proxy host and port detected");
                   var newprop = "CKMKB"
                   return this.getProperty.call(this,newprop);
                  }
                return this.getProperty(getprop);         
              }
              
          }
        catch(err) { console.error(err); } 
        try
         {  
            var NCap = Java.use("android.net.NetworkCapabilities");
            NCap.hasTransport.overload("int").implementation = function (values)
             {  
               console.log("HasTransport Check Detected ");
               if(values==4)
                  return false;
               else
                  return this.hasTransport(values);
              }
              
          }
        catch (e) { console.error(e); }
        try
         {             
            NInterface.getNetworkInterfaces.implementation = function ()
             {  
               var InterFaces = this.getNetworkInterfaces();
             //  console.log("Interface : ",JSON.stringify(InterFaces));         
                return null;       
              }
              
          }
        catch (e) { console.error(e); }        
/* ################################################################################# */
        /* Screenshot Detection Bypass 76 - 95 */
        try
          {            
             var surface_view = Java.use('android.view.SurfaceView');
             var set_secure = surface_view.setSecure.overload('boolean');
             set_secure.implementation = function(flag)
              {        
                 set_secure.call(false);
               }
             var window = Java.use('android.view.Window');
             var SFlag = window.setFlags.overload('int', 'int');
             var window_manager = Java.use('android.view.WindowManager');
             var layout_params = Java.use('android.view.WindowManager$LayoutParams');
             SFlag.implementation = function(flags, mask)
             {   
                 flags =(flags.value & ~layout_params.FLAG_SECURE.value);
                 SFlag.call(this, flags, mask);
               }
             
           }
         catch(err) { console.error(err); }
 /* ################################################################################# */
             
   /* Some Network Info */    
   var CManager = Java.use("android.net.ConnectivityManager");
   var NetInfo    = Java.use("android.net.NetworkInfo");
   NetInfo.isConnectedOrConnecting.overload().implementation = function ()
   {  console.log("isConnectedOrConnecting : ",this.isConnectedOrConnecting());
      return true ;
    }
   NetInfo.isAvailable.implementation = function ()
   { console.log("Network Available ? ")
     return true ;
   }
   CManager.getActiveNetwork.overload().implementation = function ()
   {
     console.log("getActiveNetwork : ",this.getActiveNetwork());
     return this.getActiveNetwork();
   }
   CManager.getActiveNetworkInfo.overload().implementation = function ()
   {
   //  console.log("getActiveNetworkInfo : ",this.getActiveNetworkInfo() );
     return this.getActiveNetworkInfo();
   }
   CManager.getAllNetworkInfo.overload().implementation = function ()
   { 
     console.log("getAllNetworkInfo : ",this.getAllNetworkInfo());
     // var jAndroidLog = Java.use("android.util.Log"), jException = Java.use("java.lang.Exception");
     //     console.warn("#######################\n", jAndroidLog.getStackTraceString( jException.$new() ),"#######################\n");
         
     return this.getAllNetworkInfo();
   }
   CManager.getAllNetworks.overload().implementation = function ()
   {
     console.log("getAllNetworks : ",this.getAllNetworks());
     return this.getAllNetworks();
   }
   CManager.getBoundNetworkForProcess.overload().implementation = function ()
   { 
    console.log("getBoundNetworkForProcess : ",this.getBoundNetworkForProcess());
     return this.getBoundNetworkForProcess();   
   }
   CManager.getDefaultProxy.overload().implementation = function ()
   {
    console.log("getDefaultProxy : ",this.getDefaultProxy());
     return this.getDefaultProxy();
   }
/* ################################################################################# */
  /* Program accessing /proc/self/maps and frida-agent */    
//Interceptor.attach(Module.findExportByName(null, 'open'), function (args) 
// {
    //   if((args[0].readUtf8String()).indexOf("/proc/")>=0 && (args[0].readUtf8String()).indexOf("maps")>=0 || (args[0].readUtf8String()).indexOf("frida-agent")>=0) 
    //    {
     //     console.log('open', args[0].readUtf8String());
         // args[0].writeUtf8String('echo');
  //      }
// });   
  
/* ################################################################################# */
    /* Xposed Detection Bypass */ 
   try
    {
     var cont = Java.use("java.lang.String"); 
     cont.contains.overload("java.lang.CharSequence").implementation = function (checks)
     {  
        var check = checks.toString();
        if(check.indexOf("libdexposed")>=0 || check.indexOf("libsubstrate.so")>=0 || check.indexOf("libepic.so")>=0 || check.indexOf("libxposed")>=0 )
         {
            var BypassCheck = "libpkmkb.so";
            return this.contains.call(this,BypassCheck);
         }
         return this.contains.call(this,checks);
      }
    }
    catch(erro) { console.error(erro); }
      
   try
    {
      var StacktraceEle = Java.use("java.lang.StackTraceElement");
      StacktraceEle.getClassName.overload().implementation = function ()
      {  
        var Flag = false;
        var ClazzName = this.getClassName();      
        if(ClazzName.indexOf("com.saurik.substrate.MS$2")>=0 || ClazzName.indexOf("de.robv.android.xposed.XposedBridge")>=0) 
        { 
          console.log("STE Classes : ", this.getClassName() )
          Flag = true;
          if(Flag)
           {
             var StacktraceEle = Java.use("java.lang.StackTraceElement");
             StacktraceEle.getClassName.overload().implementation = function ()
             {
               var gMN = this.getMethodName();
               if(gMN.indexOf("handleHookedMethod")>=0 || gMN.indexOf("handleHookedMethod")>=0 || gMN.indexOf("invoked")>=0)
               { 
                 console.log("STE Methods : ", this.getMethodName() );
                 return "ulala.ulala";
                } 
              return this.getMethodName();       
             }             
            }
          return "com.android.vending"
         }        
                
        return this.getClassName();
      }  
     }    
     catch(errr) { console.error(errr); }
                                  
  })
  
 