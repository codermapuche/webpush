const fs      = require('fs').promises,
      http    = require('http'),
      path    = require('path'),
      url     = require('url'),
      wp      = require('./webpush.js');

// -------------------------------------------------------------------------

// RAM Store of push suscribers for example propouses
const API = {
  _SUBS : {
  },
  'POST': {
    '/suscribe': async (sub) => {
      API._SUBS[sub.auth] = sub;
    }
  }
}

// -------------------------------------------------------------------------

// WEB PUSH Samples is here
;(async () => {

  let vapid = {
    subject: "mailto:mailbot@craving.com.ar",
    key    : path.join(__dirname, 'private.key'),
    cert   : path.join(__dirname, 'www', 'vapid.cert')
  }
  
  try {
    let keys = {
      key : await fs.readFile(vapid.key,  'ascii'),
      cert: await fs.readFile(vapid.cert, 'ascii')      
    }
    
    vapid.key  = keys.key;
    vapid.cert = keys.cert;
  } catch (err) {
    console.error(err);
    
    // 1. Generate new vapid credentials.
    let keys = wp.VAPID_generateKeys();

    await fs.writeFile(vapid.key, keys.key);
    await fs.writeFile(vapid.cert, keys.cert);

    vapid.key = keys.key;
    vapid.cert = keys.cert;
  }
  
  vapid.key = JSON.parse(vapid.key);

  setInterval(() => {
    for (let sub in API._SUBS) {
      // 2. Send push with vapid.
      wp.push(vapid, API._SUBS[sub], {
        title: 'Push ' + Date.now()     
      })
      .catch(console.error);
    }
  }, 5 * 1000);

})();

// -------------------------------------------------------------------------

// Below this line a little web server for run the example.
// You can skip the rest.

const port  = 80,
      mimes = {
        html: 'text/html',
        js:   'text/javascript',
        cert: 'text/plain',
        jpg:  'image/jpg'
      }

// -------------------------------------------------------------------------

http.createServer(async (request, response) => {
  var result = {
        error: false,
        messages: []
      },
      body = [];

  response.setHeader('Access-Control-Allow-Origin', '*');
  response.setHeader('Access-Control-Allow-Methods', 'GET, POST');
  response.setHeader('Access-Control-Allow-Credentials', true);

  if (request.url === '/') {
    request.url = '/index.html';
  }

  if (request.method === 'GET') {
    let content  = "",
        pathname = path.join(__dirname, "www", request.url),
        ext      = request.url.split('.').pop();

    try {
      content = await fs.readFile(path.join(__dirname, "www", request.url));
      response.setHeader('Content-Type', mimes[ext]);
    } catch (e) {
      result.error = true;
      result.messages.push("Not found.");
      content = JSON.stringify(result);
    }

    return response.end(content);
  }

  response.setHeader('Content-Type', 'text/json');

  request
    .on('error', (err) => {
      let content = "";

      result.error = true;
      result.messages.push(err.toString());
      content = JSON.stringify(result);

      return response.end(content);
    })
    .on('data', (chunk) => {
      body.push(chunk);
    })
    .on('end', async () => {
      body = Buffer.concat(body).toString();

      try {
        body = JSON.parse(body);
      } catch(e) {
        result.error = true;
        result.messages.push('Invalid JSON');
        content = JSON.stringify(result);

        return response.end(content);
      }

      if ( !(request.method in API) || !(request.url in API[request.method]) ) {
        result.error = true;
        result.messages.push('Invalid API');
        content = JSON.stringify(result);
        return response.end(content);
      }

      content = await API[request.method][request.url](body);
      response.end(content);
    });
})
.listen(port, (err) => {
  if (err) {
    return console.error('Something bad happened ', err)
  }

  console.log('Server is listening on ' + port);
});
