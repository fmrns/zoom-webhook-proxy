# zoom-webhook-proxy

A lightweight Node.js proxy that instantly responds to Zoom's 3-second webhook validation and asynchronously forwards the full payload to a Google Apps Script `doPost()` endpoint for further processing.

## Architecture

```
Zoom api <-(*)-> nginx - zoom-webhook-proxy(Node.js) <- (**) -> Google Apps Script
```

- `(*)` due to latency issues, direct connections from Zoom API to Google Apps Script cannot satisfy Zoom's validation requirements. additionally, Zoom does not permit redirects. therefore, the `endpoint.url_validation` event is processed by zoom-webhook-proxy.
- `(**)` the proxy forwards `x-zm-signature` and `x-zm-request-timestamp` via query string, since these HTTP headers are stripped by the Google Apps Script environment. the proxy also checks whether Google Apps Script returns the same result for `endpoint.url_validation`. if the response matches, forwarding behavior continues; otherwise, it is suspended until the next validation pass.

## Setup

### 1. Get your Zoom Webhook Secret

Visit [Zoom Marketplace](https://marketplace.zoom.us/) and create a Webhook-only app.
Copy the **Secret Token** from the app settings.

### 2. Install dependencies

```sh
npm install express axios dotenv ip-cidr ipaddr.js
```

### 3. Configure `.env`

Copy the `example.env` file to a `.env` file and fill the following:

```env
POST_URL="https://script.google.com/macros/s/.../exec"
ZOOM_SECRET="your_zoom_webhook_secret"
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
