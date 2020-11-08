# redis-loadmodbytes
redis-loadmodbytes is a redis module that provides a command to load other
redis modules over connections, removing the need for filesystem access
to the redis server.

## Installation
There are two approaches. You may configure redis to always load this module or
load it at runtime. Download a tarball or build from source, then follow
instructions [here](https://redis.io/topics/modules-intro#loading-modules).

## Usage
Once loaded, you can use `LOADMODBYTES` from a redis connection to load other
base64-encoded modules.

```
> LOADMODBYTES aW52YWxpZCBtb2...R1bGUgZXhhbXBsZQo=
successfully loaded 14314456 byte module
```

You may optionally provide configuration arguments which will be passed through
to your loaded module.

```
> LOADMODBYTES aW52YWxpZCBtb2...R1bGUgZXhhbXBsZQo= arg1 arg2 arg3
successfully loaded 14314456 byte module
```
