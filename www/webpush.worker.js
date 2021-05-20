console.log('=== WebPush Worker ===');
self.addEventListener('push', function(evt) {
	const data = evt.data.json();
	console.log('=== WebPush Event ===', data);
	self.registration.showNotification(data.title, data.message);
});