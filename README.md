# zoom-webhook-proxy

A lightweight Node.js proxy that instantly responds to Zoom's 3-second webhook validation and asynchronously forwards the full payload to a Google Apps Script `doPost()` endpoint for further processing.

## Architecture

```
Zoom api <-> nginx <- (*) -> zoom-webhook-proxy(Node.js) <- (**) -> Google Apps Script
```

- `(*)` direct connection from Zoom api to Google Apps Script is too slow to pass Zoom's validation. `endpoint.url_validation` event is processed by zoom-web-proxy.
- `(**)` forward `x-zm-signature` and `x-zm-request-timestamp` via query string. these HTTP fields are trimmed by the GAS enviromnent, so forwarding explicitly is required.

## Setup

### 1. Get your Zoom Webhook Secret

Visit [Zoom Marketplace](https://marketplace.zoom.us/) and create a Webhook-only app.
Copy the **Secret Token** from the app settings.

### 2. Install dependencies

```sh
npm install express axios dotenv
```

### 3. Configure `.env`

Create a `.env` file with the following:

```env
POST_URL=https://script.google.com/macros/s/.../exec
ZOOM_SECRET=your_zoom_webhook_secret
```

- `POST_URL`: The URL of your Google Apps Script `doPost()` endpoint
- `ZOOM_SECRET`: The secret token from your Zoom webhook app

### 4. Run the proxy server

```sh
node index.js
```

### 5. Example Nginx configuration

```nginx
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

Enjoy!
