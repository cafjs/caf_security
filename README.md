# CAF (Cloud Assistant Framework)

Co-design permanent, active, stateful, reliable cloud proxies with your web app.

See http://www.cafjs.com 

## CAF Lib Security

This repository contains a CAF lib to add security checks.


## API

    lib/proxy_security.js
 
## Configuration Example

### framework.json

       "plugs": [
        {
            "module": "caf_security/plug",
            "name": "security_mux",
            "description": "Authenticates requests\n Properties: <strategy> Name for the authentication mechanism \n <tokenKey> Secret to sign tokens \n <tokenExpires> Validity in seconds of a token\n <users> username/hashed passwords for valid users\n",
            "env": {
                "strategy" : {
                    "local":  {
                        "tokenExpires" : 50000,
                        "tokenKey" : "pleasechange",
                        "users" : {
                            "antonio" : "sha1$c414d4b2$1$9920e4c8d3d8a7f1db37867e55240e2dfa482c26",
                            "john" :"sha1$3f1d4cdf$1$a33427e0ebb54df43e365d6effc55c1683f142e6"
                        }
                    },
                    "accounts": {
                        "serviceUrl" : "http://accounts.cafjs.com/app.html",
                        "pubFile" : "rsa_pub.pem",
                        "unrestricted" : false
                    }
                }
            }
        }
        
        
In the example above we enable two authentication policies:

*  *local* Insecure, use only for debugging. It uses a shared key to encrypt tokens that all apps should know. We add password hashes of users using `nodepw` in the npm package  `password-hash`.

*  *accounts* Uses an external authentication service that signs tokens with an asymmetric key (RSA). The file `rsa_pub.pem` (in the same directory as `framework.json`) contains the service public key (self-signed certificate in PEM format, see `openssl`). The property `unrestricted` is a suggestion that this app needs a token that can be used to authenticate to any application; the end user is prompted to confirm  this request, and should only grant it for trusted apps.
    

### ca.json

    "internal" : [
        {
            "module": "caf_security/plug_ca",
            "name": "security_ca",
            "description": "Authorization checks for this CA",
            "env" : {

            }
        }
        ...
     ]
     "proxies" : [
       {
            "module": "caf_security/proxy",
            "name": "security",
            "description": "Proxy to security services for this CA",
            "env" : {

            }
        }
        ...
      ]
  
  
    
        
            
 
