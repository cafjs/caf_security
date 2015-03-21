# CAF (Cloud Assistant Framework)

Co-design permanent, active, stateful, reliable cloud proxies with your web app.

See http://www.cafjs.com 

## CAF Lib Security

[![Build Status](http://ci.cafjs.com/github.com/cafjs/caf_security/status.svg?branch=master)](http://ci.cafjs.com/github.com/cafjs/caf_security)


This repository contains a CAF lib to add security checks.


## API

    lib/proxy_security.js
 
## Configuration Example

### framework.json

       "plugs": [
        {
            "module": "caf_security/plug",
            "name": "security",
            "description": "Authenticates requests\n Properties: <keysDir> Directory with key material, defaults to colocated with ca_methods.js (i.e., <app_root>/lib).\n <trustedPubKeyFile> Trusted public key to verify signed tokens. \n <privateKeyFile> Optional private key to sign tokens. \n <pubKeyFile> Optional public key for signing key. \n <appPublisher> Name of the app publisher.\n <appLocalName> Local name app given by the app publisher.\n <allowNobodyUser> Enable the user 'nobody' to bypass authentication",
            "env": {
                        "keysDir": null,
                        "trustedPubKeyFile" : "trusted_pub.pem",
                        "privateKeyFile": null,
                        "publicKeyFile" : null,
                        "appPublisher" : "d41d8cd98a00b204e9700988ecf8427e",
                        "appLocalName" : "myApp",
                        "allowNobodyUser" : false
                        
                    }
                }
            }
        }
        
        
The above example uses an external authentication service that signs tokens with an asymmetric key (RSA). The file `trustedPubKeyFile` (in the same directory as `ca_methods.js` or absolute path) contains the service public key (self-signed certificate in PEM format, see `openssl`).

Instead, if this plug can sign tokens on its own, the `serviceURL` is `null` and the files `privateKeyFile` and `pubKeyFile` provide the asymmetric key.

The property `unrestricted` is a suggestion that this app needs a token that can be used to authenticate to any application; the end user is prompted to confirm  this request, and should only grant it for trusted apps.
    

### ca.json


    {
            "module": "caf_security#plug_ca",
            "name": "security",
            "description": "Authorization checks for this CA".",
            "env" : {
                "maxRetries" : "$._.env.maxRetries",
                "retryDelay" : "$._.env.retryDelay"
            },
            "components" : [
                {
                    "module": "caf_security#proxy",
                    "name": "proxy",
                    "description": "Proxy to security services for this CA",
                    "env" : {
                          ...
                    }
                }
            ]
    }
    
        
            
 
