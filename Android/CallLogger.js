
function ProcessName() {
    var openPtr = Module.getExportByName('libc.so', 'open');
    var open = new NativeFunction(openPtr, 'int', ['pointer', 'int']);
    var readPtr = Module.getExportByName('libc.so', 'read');
    var read = new NativeFunction(readPtr, 'int', ['int', 'pointer', 'int']);
    var closePtr = Module.getExportByName('libc.so', 'close');
    var close = new NativeFunction(closePtr, 'int', ['int']);
    var path = Memory.allocUtf8String('/proc/self/cmdline');
    var fd = open(path, 0);
    if (fd != -1) {
        var buffer = Memory.alloc(0x1000);
        var result = read(fd, buffer, 0x1000);
        close(fd);
        result = ptr(buffer).readCString();
        return result;
    }
    return -1;
}

function mkdir(path) {
    var mkdirPtr = Module.getExportByName('libc.so', 'mkdir');
    var mkdir = new NativeFunction(mkdirPtr, 'int', ['pointer', 'int']);
    var opendirPtr = Module.getExportByName('libc.so', 'opendir');
    var opendir = new NativeFunction(opendirPtr, 'pointer', ['pointer']);
    var closedirPtr = Module.getExportByName('libc.so', 'closedir');
    var closedir = new NativeFunction(closedirPtr, 'int', ['pointer']);
    var cPath = Memory.allocUtf8String(path);
    var dir = opendir(cPath);
    if (dir != 0) {
        closedir(dir);
        return 0;
    }
    mkdir(cPath, 755);
    chmod(path);
}

function chmod(path) {
    var chmodPtr = Module.getExportByName('libc.so', 'chmod');
    var chmod = new NativeFunction(chmodPtr, 'int', ['pointer', 'int']);
    var cPath = Memory.allocUtf8String(path);
    chmod(cPath, 755);
}

function Hooks() {

var Process = ProcessName();
//var Process ="YourProcessNameHere"; //some app complaint for ProcessName() not create directory , no idea why
var SetupPath = 'data/data/'+Process+'/analyze/';
mkdir(SetupPath);
var OpenPath = '/data/data/'+Process+'/analyze/open.txt';
var FOpenPath = '/data/data/'+Process+'/analyze/fopen.txt';
var StatPath = '/data/data/'+Process+'/analyze/stat.txt';
var AccessPath = '/data/data/'+Process+'/analyze/access.txt';
var SystemPath = '/data/data/'+Process+'/analyze/system.txt';
var OpenDirPath = '/data/data/'+Process+'/analyze/opendir.txt';
var ReadDirPath = '/data/data/'+Process+'/analyze/readdir.txt';
var faccessatPath = '/data/data/'+Process+'/analyze/faccessat.txt';
var dlopenPath = '/data/data/'+Process+'/analyze/dlopen.txt';
var StrCmpPath = '/data/data/'+Process+'/analyze/strcmp.txt';
var StrStrPath = '/data/data/'+Process+'/analyze/strstr.txt';
var FgetsPath = '/data/data/'+Process+'/analyze/fgets.txt';
var MemCpyPath = '/data/data/'+Process+'/analyze/memcpy.txt';
var StrLenPath = '/data/data/'+Process+'/analyze/strlen.txt';
var StrCatPath = '/data/data/'+Process+'/analyze/strcat.txt';
var SystemPropertyPath = '/data/data/'+Process+'/analyze/systemproperyget.txt';
var Open = new File(OpenPath,'wb');
var FOpen = new File(FOpenPath,'wb');
var Stat = new File(StatPath,'wb');
var System = new File(SystemPath,'wb');
var Access = new File(AccessPath,'wb');
var OpenDir = new File(OpenDirPath,'wb');
var ReadDir = new File(ReadDirPath,'wb');
var Faccessats = new File(faccessatPath,'wb');
var dlopen = new File(dlopenPath,'wb');
var StrStr = new File(StrStrPath, 'wb');
var StrCmp = new File(StrCmpPath, 'wb');
var FGets = new File(FgetsPath, 'wb');
var MemCpy = new File(MemCpyPath , 'wb');
var StrLen = new File(StrLenPath, 'wb');
var StrCat = new File(StrCatPath, 'wb');
var SystemProperty = new File(SystemPropertyPath, 'wb');
Interceptor.attach(Module.findExportByName(null, 'faccessat'), function (args) {
  Faccessats.write('faccessat: '+args[1].readUtf8String()+'\n');
  Faccessats.flush();
});

Interceptor.attach(Module.findExportByName(null, 'open'), function (args) {       
     Open.write('Open: '+args[0].readCString()+'\n');
     Open.flush();            
});

Interceptor.attach(Module.findExportByName(null, 'fopen'), function (args) {       
     FOpen.write('Fopen: '+args[0].readCString()+'\n');
     FOpen.flush();            
});

Interceptor.attach(Module.findExportByName(null, 'stat'), function (args) {
     Stat.write('Stat: '+args[0].readUtf8String()+'\n');
     Stat.flush();
});

Interceptor.attach(Module.findExportByName(null, 'access'), function (args) {   
     Access.write('Access: '+args[0].readUtf8String()+'\n');
     Access.flush();        
});

Interceptor.attach(Module.findExportByName(null, 'opendir'), function (args) {
     OpenDir.write('OpenDir: '+args[0].readUtf8String()+'\n');
     OpenDir.flush(); 
});

Interceptor.attach(Module.findExportByName(null, 'system'), function (args) {
    System.write('System: '+args[0].readUtf8String()+'\n');
    System.flush();
});

Interceptor.attach(Module.findExportByName(null, 'android_dlopen_ext'),function (args) {             
      dlopen.write("android_dlopen_ext: "+args[0].readCString()+'\n'); 
      dlopen.flush();      
});

Interceptor.attach(Module.findExportByName(null, 'strcmp'),function (args) {             
      StrCmp.write("strcmp: "+args[0].readUtf8String()+ " == "+args[1].readUtf8String()+'\n'); 
      StrCmp.flush();      
});
Interceptor.attach(Module.findExportByName(null, 'strstr'),function (args) {             
      StrStr.write("strstr: "+args[0].readCString()+ " => "+args[1].readCString()+'\n'); 
      StrStr.flush();        
});
  
Interceptor.attach(Module.getExportByName(null, 'readdir'), new CModule(`
  #include <gum/guminterceptor.h>
  #include <stdio.h>
  #include <string.h>
  #define MODULE_AUTHOR Yuvraj Saxena
  #define DATE_CREATED 30/10/2020
  struct dirent {
    uint64_t         d_ino;
    int64_t          d_off;
    unsigned short   d_reclen;
    unsigned char    d_type;
    char             d_name[500];
  };
  struct DIR {
  	int fd_;
  	size_t available_bytes_;
  	struct dirent* next_;
  };
	
  typedef struct DIR DIR;
  extern void onMessage (const gchar * message);
  static void log (const gchar * format, ...);
  void onEnter (GumInvocationContext * ic) {
    DIR *de;
    de = (DIR*) gum_invocation_context_get_nth_argument (ic, 0);
    if(de->next_!=NULL&&de->next_->d_name!=NULL)
    	log("readdir(%s)", de->next_->d_name);
  }
  static void log (const gchar * format, ...) {
    gchar * message;
    va_list args;
    va_start (args, format);
    message = g_strdup_vprintf (format, args);
    va_end (args);
    onMessage (message);
    g_free (message);
  }
`, { 
  onMessage: new NativeCallback(messagePtr => {
    const message = messagePtr.readCString();
    ReadDir.write(message+'\n');
    ReadDir.flush();
  }, 'void', ['pointer'])}));


var fgetsPtr = Module.findExportByName("libc.so", "fgets");
var fgets = new NativeFunction(fgetsPtr, 'pointer', ['pointer', 'int', 'pointer']);
Interceptor.replace(fgetsPtr, new NativeCallback(function(buffer, size, fp) {
    var retval = fgets(buffer, size, fp);
    var bufstr = Memory.readUtf8String(buffer);
    FGets.write("fgets : "+bufstr);
    FGets.flush();
    if (bufstr.indexOf("TracerPid:") > -1) {
        Memory.writeUtf8String(buffer, "TracerPid:\t0");      
    }
    return retval;
}, 'pointer', ['pointer', 'int', 'pointer']))

Interceptor.attach(Module.findExportByName(null, 'memcpy'),function (args) {             
       MemCpy.write("memcpy : "+args[0].readCString()+ " => "+args[1].readCString()+'\n'); 
       MemCpy.flush();        
});

Interceptor.attach(Module.findExportByName(null, 'strlen'),function (args) {             
       StrLen.write("strlen : "+args[0].readCString()+'\n'); 
       StrLen.flush();        
});

Interceptor.attach(Module.findExportByName(null, 'strcat'),function (args) {             
       StrCat.write("strcat : "+args[0].readCString()+ " => "+args[1].readCString()+'\n');  
       StrCat.flush();        
});


Interceptor.attach(Module.findExportByName(null, '__system_property_get'), function (args) {
        SystemProperty.write('__system_property_get : '+args[0].readUtf8String()+'\n');     
        SystemProperty.flush();   
});

Interceptor.attach(Module.findExportByName(null, 'read'), function (args) {
      //  console.log('read: '+args[1].readCString()+'\n');     
        
});

Java.perform(function ()  {	
	    var JavaFiles = '/data/data/'+Process+'/analyze/javafiles.txt';
        var JavaFile = new File(JavaFiles,'wb');    		
		var file = Java.use("java.io.File");
		file.$init.overload("java.lang.String").implementation = function(path){
			JavaFile.write("[*] NFile Create Path: " + path+'\n');
			JavaFile.flush()
			return file.$init.overload("java.lang.String").call(this, path);
		}
		file.$init.overload("java.io.File", "java.lang.String").implementation = function(fileObject, path){
			JavaFile.write("[*] NFile PO: " + fileObject.toString() +"/"+ path+'\n' );
			JavaFile.flush();
			return file.$init.overload("java.io.File", "java.lang.String").call(this, fileObject, path);
		}
		file.$init.overload("java.lang.String", "java.lang.String").implementation = function(parent, path){
			JavaFile.write("[*] NFile PP : " + parent+"/" +path +'\n' );
			JavaFile.flush();
			return file.$init.overload("java.lang.String", "java.lang.String").call(this, parent, path);
		}
		file.$init.overload("java.net.URI").implementation = function(neturi){
			JavaFile.write("[*] New File URI: " + neturi.toString()+'\n');
			JavaFile.fluash();
			return file.$init.overload("java.net.URI").call(this, neturi);
		}		
		var is = Java.use("java.io.InputStream");
		is.read.overload().implementation = function(){
			var ret = is.read.overload().call(this);
			JavaFile.write("InputStream.read()", ret + '\n')
			JavaFile.flush();
			return ret;
		}	
		var SocketJava = '/data/data/'+Process+'/analyze/socket.txt';
        var Sockets = new File(SocketJava,'wb');    
		var sock = Java.use("java.net.Socket");				
		sock.bind.implementation = function(localAddress){
			Sockets.write("Bind("+localAddress.toString()+")\n");
			Sockets.flush();
			sock.bind.call(this, localAddress);
		}			
		sock.connect.overload("java.net.SocketAddress").implementation = function(endPoint){
			Sockets.write("Connect("+endPoint.toString()+")\n");
			Sockets.flush();
			sock.connect.overload("java.net.SocketAddress").call(this, endPoint);
		}				
		sock.connect.overload("java.net.SocketAddress", "int").implementation = function(endPoint, tmout){
			Sockets.write("Connect["+endPoint.toString()+", Timeout: "+tmout+"]\n");
			Sockets.flush();
			sock.connect.overload("java.net.SocketAddress", "int").call(this, endPoint, tmout);
		}		
		sock.getInetAddress.implementation = function(){
			ret = sock.getInetAddress.call(this);
			Sockets.write("GetInetAddress  ",ret.toString()+'\n');
			Sockets.flush();
			return ret;
		}
		sock.$init.overload("java.net.InetAddress", "int").implementation = function(inetAddress, port){
			Sockets.write("new Socket('"+inetAddress.toString()+"', "+port+") called\n");
			Sockets.flush();
			this.$init.overload("java.net.InetAddress", "int").call(this, inetAddress, port);
		}
		sock.$init.overload("java.net.InetAddress", "int","java.net.InetAddress", "int").implementation = function(inetAddress, port, localInet, localPort){
			Sockets.write("RemoteInet: '"+inetAddress.toString()+"', RemotePort"+port+", LocalInet: '"+localInet+"', LocalPort: "+localPort+")\n");
			Sockets.flush();
			this.$init.overload("java.net.InetAddress", "int","java.net.InetAddress", "int").call(this, inetAddress, port);
		}		
		sock.$init.overload("java.net.Proxy").implementation = function(proxy){
			Sockets.write("Proxy: "+proxy.toString()+")\n");
			Sockets.flush();
			this.$init.overload("java.net.Proxy").call(this, proxy);
		}				
		sock.$init.overload("java.net.SocketImpl").implementation = function(si){
			Sockets.write("SocketImpl: "+si.toString()+")\n");
			Sockets.flush();
			this.$init.overload("java.net.SocketImpl").call(this, si);
		}			
		sock.$init.overload("java.lang.String", "int", "java.net.InetAddress", "int").implementation = function(host,port, localInetAddress, localPort){
			Sockets.write("Host: '"+host+"', RemPort: "+port+", LocalInet: '"+localInetAddress+"', localPort: "+localPort+")\n");
			Sockets.flush();
			this.$init.overload("java.lang.String", "int", "java.net.InetAddress", "int").call(this, si);
		}
		
		 var Base64FilePath = '/data/data/'+Process+'/analyze/base64.txt';
         var Base64File = new File(Base64FilePath,'wb');      
         var Base64 = Java.use("android.util.Base64"); 
         Base64.decode.overload("java.lang.String", "int").implementation = function(encoded, value) {
                    Base64File.write("Base64 Encode : "+encoded+'\n');     
                    var ret = this.decode.call(this, encoded, value);
                    var buffer = Java.array('byte', ret);
                    var result = "";
                    for (var i = 0; i < buffer.length; ++i) {
                        result += (String.fromCharCode(buffer[i] & 0xff));
                    }
                    Base64File.write("Base64 Decode : "+JSON.stringify(result.toString())+'\n');
                    Base64File.flush();
                    return this.decode.call(this, encoded, value);
            };
          var JavaComparePath = '/data/data/'+Process+'/analyze/javacompare.txt';
          var JavaCompare = new File(JavaComparePath,'wb');        
          var StringCompare = Java.use('java.lang.String'), objectClass = 'java.lang.Object';
          StringCompare.equals.overload(objectClass).implementation = function(obj)
          {
            var response = StringCompare.equals.overload(objectClass).call(this, obj);                     
            JavaCompare.write(StringCompare.toString.call(this) + ' === ' + obj.toString() + ' ? ' + response +'\n');              
            JavaCompare.flush()
            return response;                 
           }
                                            																										
	})

}
setImmediate(Hooks);
