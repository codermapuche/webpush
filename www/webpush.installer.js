const WebPush = {
	suscribe: function (record) {			
		if (Notification.permission === 'denied') {
			return Promise.reject('User has blocked push notification.');
		}

		if ( !('PushManager' in window) ) {
			return Promise.reject('Sorry, Push notification isn\'t supported in your browser.');
		}
	
		return WebPush
			.request("GET", "/vapid.cert", {})
			.then(function(applicationServerKey) {				
				return record.pushManager.subscribe({
					userVisibleOnly: true,
					applicationServerKey: WebPush.encode(applicationServerKey)
				});
			});		
	},
	ready: function (subscription) {
		return navigator
			.serviceWorker
			.ready
			.then(function() { 
				return subscription; 
			});
	},
	register: function (subscription) {
		return Promise.all([
			WebPush.getKey(subscription, 'auth'),
			WebPush.getKey(subscription, 'p256dh')
		])
		.then(function(keys) {
			const sub = {
				auth: keys[0],
				p256dh: keys[1],
				endpoint: subscription.endpoint
			}
			
			return WebPush.request("POST", "/suscribe", sub);
		});		
	},
	getKey: function (subscription, name) {	
    return new Promise(function(res) {
			const key = new Blob([ subscription.getKey(name) ]),
						reader = new FileReader();
						
			reader.onload = function(evt) { res(evt.target.result.split(',').pop()); }
			reader.readAsDataURL(key);			
		});
  },
	request: function (method, path, body) {	
    return new Promise(function(res, rej) {			
			const xhttp = new XMLHttpRequest();
			
			xhttp.onreadystatechange = function() {
				if (this.readyState != 4) {
					return;
				}
				
				if (this.status != 200) {
					return rej(xhttp.responseText);
				}
				
				res(xhttp.responseText);
			}
			
			xhttp.open(method, path, true);
			xhttp.send(JSON.stringify(body));		
		});
  },
	encode: function (b64) {		
		b64 += '='.repeat((4 - b64.length % 4) % 4);
		
    b64 = b64.replace(/-/g, '+')
						 .replace(/_/g, '/');
   
    b64 = window.atob(b64);
		
    const oArr = new Uint8Array(b64.length);
   
    for (var i = 0; i < b64.length; ++i) {
      oArr[i] = b64.charCodeAt(i);
    }
		
    return oArr;
  }
}
			
navigator
	.serviceWorker
	.register('./webpush.worker.js', { scope: '/' })
	.then(WebPush.ready)
	.then(WebPush.suscribe)
	.then(WebPush.register)
	.catch(console.error);