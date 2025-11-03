#### zoom-webhook-proxy

---

A lightweight Node.js proxy that instantly responds to Zoom’s 3-second webhook validation and asynchronously forwards the full payload to a Google Apps Script doPost endpoint for further processing.

#### setup

---

1. Get your Zoom Webhook Secret
Visit [Zoom Marketplace](https://marketplace.zoom.us/) and create a Webhook-only app. Copy the Secret Token from the app settings.

2. Install dependencies
```
npm install express axios dotenv
```

3. Configure .env
POST_URL:  The URL of your endpoint, such as GAS `doPost()`
ZOOM_SECRET:  The secret token from your Zoom webhook app

4. Run the proxy server
```
node index.js
```

5. Example Nginx configuration
```
location "/zoom-webhook-proxy" {
  proxy_pass         http://127.0.0.1:3000/zoom-webhook-proxy;
  proxy_http_version 1.1;
  proxy_set_header   Host $host;
  proxy_set_header   X-Real-IP              $remote_addr;
  proxy_set_header   X-Forwarded-For        $proxy_add_x_forwarded_for;
  proxy_set_header   X-Forwarded-Proto      $http_x_forwarded_proto;
  proxy_set_header   X-Zm-Signature         $http_x_zm_signature;
  proxy_set_header   X-Zm-Request-Timestamp $http_x_zm_request_timestamp;
}
```
