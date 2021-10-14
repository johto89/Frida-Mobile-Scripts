setImmediate(function() 
{
   

   Java.perform ( function() 
   {  
   
    try{
	  var EV= Java.use("com.android.org.conscrypt.OpenSSLSignature");
	  EV.engineVerify.overload('[B').implementation = function (signatures)
	  {     console.warn("engineVerify From Conscrypt Fixed");
	        return true;
	   } }
	  catch(e){}
	  try{
	  var EV= Java.use("org.apache.harmony.xnet.provider.jsse.OpenSSLSignature");
	  EV.engineVerify.overload('[B').implementation = function (signatures)
	  {     console.warn("engineVerify From Harmoney.xnet Fixed");
	        return true;
	   } }
	   catch(e){}
	  
	  var  VerifySign= Java.use("java.security.Signature");
      VerifySign.verify.overload('[B').implementation = function (paramBool)
	   {    console.warn("Verify From java.security.Signature Fixed");	       
	        return true;	 
	   }
	   var MD = Java.use("java.security.MessageDigest");
       MD.isEqual.overload("[B", "[B").implementation = function() 
       {	       
	       return true;
        } 
     
      var INTENT = Java.use("android.content.Intent");
	      
	  Java.choose("android.content.Intent",{
      onMatch : function(instance) {
      
	  if(instance.getAction()=="com.android.vending.billing.InAppBillingService.BIND" ) 
	  {
	           
	      INTENT.setPackage.overload('java.lang.String').implementation = function (pkg)
	       {		          		
	        if(pkg=='com.android.vending')
		    { 
		    var pkgFix= "com.android.vendinf";
		    console.warn("setPackage IAP Fixed");		
	        return this.setPackage.call(this,pkgFix);	        
		    }
		  else
		    { 
     		 return this.setPackage.call(this,pkg);
		     }     
		   } 
	  }
	  else  
	  if(instance.getAction()=="com.android.vending.licensing.ILicensingService") 
	  {         
		   INTENT.setPackage.overload('java.lang.String').implementation = function (pkg)
		   {   		     		   
	          if(pkg=='com.android.vending')
		      { 
		       var pkgFix= "com.android.vendinf";
		        console.warn("setPackage LVL Fixed");		
	           return this.setPackage.call(this,pkgFix);	        
		      }
		  else
		    { 
     		    return this.setPackage.call(this,pkg);
		     } 
		   } 
      }
          		
	  },
	  onComplete :function(){}
	  
	  });
   })
});
	 
