# CAF (Cloud Assistant Framework)

Co-design permanent, active, stateful, reliable cloud proxies with your web app or gadgets.

See http://www.cafjs.com

## CAF Security Library
[![Build Status](http://ci.cafjs.com/api/badges/cafjs/caf_security/status.svg)](http://ci.cafjs.com/cafjs/caf_security)

This repository contains a CAF library to add security checks.

The goal is to help application writers to support collaborative multi-tenancy within one app.

CAF.js runs each application in a separate process, and the framework is under the control of the application writer. Therefore, the service provider, or other applications, should not trust those processes.

Also, we do not expect applications to run untrusted code in the Cloud. However, CAF.js tries very hard to minimize the impact of programming mistakes, such as trusting user input too much.

### Naming

It's all in the name.

Borrowing ideas from SDSI (Rivest&Lampson'96), we use local namespaces that can be globally identified because the `owner` of the namespace has a unique name that we can authenticate. For example, the hash of a public key can be assumed to be unique, or a username in our `accounts` service, since this service also has a public/private key pair.

And this allow us to **link** local namespaces in a robust manner. Similar to a symbolic link in a sensible file system, a name in a local namespace can refer to a named resource in a different local namespace.

Moreover, a local name can refer to a group of resources, similar to referring to a sub-directory with symbolic links. Also, a resource could have many names. Names become user-friendly tags that help us find resources.

Given a local name, how do we find its resources? By computing the transitive closure: start with local resources or referrals, both matching the target name; then, follow links, and keep adding reachable resources.

What resources are registered in a CAF.js local namespace? **Everything**

* CA:  using a  `caOwner-caLocalName` convention.
* `SharedMap`: scoped by the CA that owns it, i.e.,
`caOwner-caLocalName-mapLocalName`.
* Private pub/sub channels: to enforce that only one CA can publish, i.e.,  `caOwner-caLocalName-channelLocalName`
* Application: named after `appPublisher-appLocalName`.
* Docker Images: similarly, `imgPublisher-imgLocalName`.
* ...

Two practical considerations:

* We sometimes use resource names as hostnames and, we need to
restrict characters to ASCII letters and numbers (see RFC 1123).

* We can use the same `caLocalName` in different applications. Therefore, we
may need to qualify a CA name with its app name to make it globally unique. Applications do not trust each other, and therefore, this is almost never needed.

### Authorization

A core CAF.js abstraction is a trusted bus that is internal to an application. CAs interact with each other using this bus, and the bus guarantees that every request is authenticated by the source CA.

This allows the destination CA to grant or deny the request based on the method invoked and the caller. Also, application code has access to the caller's name, and it can impose extra requirements based on the call arguments.

CAF.js naming helps us describe access policy. Explicit ownership in the name makes it easier to allow any CA from a trusted owner, or CAs with the same owner. Names naturally support groups, and by linking, we can delegate the creation of a group to third parties. We can also group methods, further simplifying policy description.

Linked local namespaces are implemented with `AggregateMaps` (see {@link external:caf_sharing/AggregateMap}) not with certificates as in SDSI. These distributed data structures can only be written by its owner, and the trusted bus that propagates updates to replicas enforces that property. This has important advantages:

* Owners do not need to manage private keys.
* Discovery is efficient, and transparently managed by the framework.
* Revocation is fast (milliseconds).
* Changes to an `AggregateMap` respect *Writer Atomicity*, *Readers Isolation*, *Fairness*, and monotonic read consistency (see {@link external:caf_sharing}), eliminating dangerous transients when policy changes.

### Authentication

A client needs to create a mutually-authenticated secure channel to its CA. The challenge is how to provide single sign-on to multiple app CAs, when apps are not equally trusted. Client credentials used with one CA could be abused to access a more trusted CA.

We use JSON Web Tokens (JWT) signed by a third-party service, i.e., `accounts`,
to weaken authentication credentials. Tokens can be scoped to a local name within an application. Local names could belong to other namespaces, federating authentication. A simple mechanism to weaken tokens enables a privileged CA to manage tokens on behalf of a client. See {@link module:caf_security/tokens}.

Password-based authentication with the `accounts` service is based on SRP. SRP derives a strong shared secret from a weak one, while being immune to man in the middle attacks. We use this strong secret to encrypt the JSON Web Token.
