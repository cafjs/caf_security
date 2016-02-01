# CAF (Cloud Assistant Framework)

Co-design permanent, active, stateful, reliable cloud proxies with your web app.

See http://www.cafjs.com 

## CAF Lib Security
[![Build Status](http://ci.cafjs.com/api/badges/cafjs/caf_security/status.svg)](http://ci.cafjs.com/cafjs/caf_security)


This repository contains a CAF lib to add security checks.


## API

    lib/proxy_security.js
 
## Configuration Example

### framework.json

        {
            "module": "caf_security#plug",
            "name": "security",
            "description": "Authenticates requests\n Properties: <keysDir> Directory with key material, defaults to colocated with ca_methods.js (i.e., <app_root>/lib).\n <trustedPubKeyFile> Trusted public key to verify signed tokens. \n <privateKeyFile> Optional private key to sign tokens. \n <pubKeyFile> Optional public key for signing key. \n <allowNobodyUser> Enable the user 'nobody' to bypass authentication\n <accountsURL> Optional URL of an external service for user authentication.",
            "env": {
                        "keysDir": null,
                        "trustedPubKeyFile" : "trusted_pub.pem",
                        "privateKeyFile": null,
                        "publicKeyFile" : null,
                        "allowNobodyUser" : false,
                        "accountsURL" : "https://root-accounts.vcap.me:3001"
                    }
                }
            }
        }
        
        
The above example uses an external authentication service that signs tokens with an asymmetric key (RSA). The file `trustedPubKeyFile` (in the same directory as `ca_methods.js` or in `keysDir` path) contains the `accounts` service public key (self-signed certificate in PEM format, see `openssl`).

If instead this plug can sign tokens on its own, e.g., it is implementing the `accounts` service itself, the `accountsURL` is `null` and the files `privateKeyFile` and `pubKeyFile` provide the asymmetric key.


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
    
        
            
 
