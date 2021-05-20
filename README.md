# webpush
Zero dependecies, working webpush in less than 250 lines of code


## Test
Just run _node example.js_

## API

```javascript

const wp = require('webpush');

// Generate new keypair of key and cert for server
//   we need to do this one time and store for reuse
//   like a HTTPS certificates files, for be clear.
let id = wp.vapid();
await fsp.writeFile('private.key', id.key);
await fsp.writeFile('www/vapid.cert', id.cert);

// Send notification is easy, we ned a sub info
//   what income from the frontend of suscription
//   and a notification to send:
let sub = { auth, p256dh, endpoint } // <- Icome from the frontend at suscription time.
let notify = { title: 'Push ' + Date.now() };
await wp.push(id, sub, notify);
```

## Why?

Why with less than 250 lines and zero dependecies is a good alternative to:
```
cloc https://github.com/web-push-libs/web-push 

      18 dependecies.
     147 text files.
     144 unique files.
      83 files ignored.

-------------------------------------------------------------------------------
Language                     files          blank        comment           code
-------------------------------------------------------------------------------
Javascript                      70           1454            874           8377
JSON                            19              0              0           1397
TypeScript                       9             55            190            479
DOS Batch                        1              2              0             15
PowerShell                       1              1              3             14
Bourne Shell                     1              2              0             13
YAML                             2              0              0             12
-------------------------------------------------------------------------------
SUM:                           103           1514           1067          10307
-------------------------------------------------------------------------------
```