//  -*- coding: us-ascii -*-
//
//  Released under MIT License
//
//  Copyright(c) 2025 Fumiyuki Shimizu
//  Copyright(c) 2025 Abacus Technologies, Inc.
//
//  Permission is hereby granted, free of charge, to any person
//  obtaining a copy of this software and associated documentation files
// (the "Software"), to deal in the Software without restriction,
//  including without limitation the rights to use, copy, modify, merge,
//  publish, distribute, sublicense, and / or sell copies of the Software,
//  and to permit persons to whom the Software is furnished to do so,
//  subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be
//  included in all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
//  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
//  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
//  NONINFRINGEMENT.IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
//  BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
//  ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
//  CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//  SOFTWARE.

require('dotenv').config({ path: __dirname + '/.env' });
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const ipaddr = require('ipaddr.js');
const cidr = require('ip-cidr').default;

const SIGNATURE_KEY = 'x-zm-signature';
const TIMESTAMP_KEY = 'x-zm-request-timestamp';

const PORT = process.env.PORT || 3000;
const ZOOM_SECRET = process.env.ZOOM_SECRET;
const POST_URL = process.env.POST_URL; // "https://script.google.com/macros/s/.../exec
const TIMESTAMP_TOLERANCE_SEC = parseInt(process.env.TIMESTAMP_TOLERANCE_SEC, 10);
const ALLOWED_WEBHOOK_CIDR_LIST = process.env.ALLOWED_WEBHOOK_CIDR_LIST
  .split(',')
  .map(c => new cidr(c.trim()));


/**
 * @param {string} ip
 * @param {cidr[]} cidrList
 * @returns {boolean}
 */
function isIPIn(ip, cidrList) {
  try {
    const norm = ipaddr.parse(ip);
    const remoteAddr = (norm.kind() === 'ipv6' && norm.isIPv4MappedAddress())
      ? norm.toIPv4Address().toString()
      : norm.toString();
    return cidrList.some(c => c.contains(remoteAddr));
  } catch (err) {
    console.error('failed: ', err.message);
    return false;
  }
}

/**
 * @param {string} signature
 * @param {string} timestamp
 * @param {string} body
 * @returns {boolean}
 */
function isValidSignature(signature, timestamp, body) {
  const hash = crypto
    .createHmac('sha256', ZOOM_SECRET)
    .update(`v0:${timestamp}:${body}`)
    .digest('hex');
  return `v0=${hash}` === signature;
}

const app = express();
app.set('trust proxy', true); // Nginx
//app.use(bodyParser.json());
app.use(bodyParser.json({
  // avoid re-serializing... cf. JCS
  // xxx `v0:${timestampValue}:${JSON.stringify(req.body)}`;
  verify: (req, res, buf) => {
    req.fmsRawBody = buf.toString('utf8');
  }
}));

let isForwardAllowed = true;
app.post('/zoom-webhook-proxy', async (req, res) => {
  const nw = new Date().getTime() / 1000;

  let remoteAddr = req.ip || req.connection.remoteAddress;
  if (!isIPIn(remoteAddr, ALLOWED_WEBHOOK_CIDR_LIST)) {
    console.warn(`invalid remote: ${remoteAddr}`);
    return res.status(403).send('request denied: IP address not allowed.');
  }

  const signatureValue = req.headers?.[SIGNATURE_KEY] || null;
  const timestampValue = req.headers?.[TIMESTAMP_KEY] || null;
  const timestampInt = timestampValue ? parseInt(timestampValue, 10) : -1;

  if (timestampInt < nw - TIMESTAMP_TOLERANCE_SEC || timestampInt > nw) {
    console.warn(`remote: ${remoteAddr}: invalid timestamp: ${timestampInt} now: ${nw}`);
    return res.status(403).send('invalid timestamp');
  }

  let hashedToken;
  const isEndpointValidation = (req.body.event === 'endpoint.url_validation');
  if (isEndpointValidation) {
    const plainToken = req.body.payload.plainToken;
    hashedToken = crypto
      .createHmac('sha256', ZOOM_SECRET)
      .update(plainToken).digest('hex');
    const responseBody = {
      plainToken,
      encryptedToken: hashedToken
    };
    res.status(200).json(responseBody);

    // ***************************************************************
    // validation requires an immediate response. in other words, the
    // proxy must not forward the request to the destination and then
    // return the response to Zoom. instead, it must generate and
    // return the response directly, as shown above. the following
    // code verifies that the correct response has been generated and
    // returned.
    // ***************************************************************
  } else if (!isValidSignature(signatureValue, timestampValue, req.fmsRawBody)) {
    console.warn(`remote: ${remoteAddr}: invalid signature.`);
    return res.status(403).send('invalid signature');
  }

  try {
    if (!isForwardAllowed && !isEndpointValidation) {
      console.warn(`remote: ${remoteAddr}: something wrong with the destination: ${POST_URL}`);
      return res.status(403).send('request blocked due to suspicious proxy destination');
    }

    console.log('remote: ${remoteAddr}: forwarding event: ', req.body.event);
    const query = new URLSearchParams({
      http_x_zm_signature: signatureValue,
      http_x_zm_request_timestamp: timestampValue
    });
    const responseGAS = await axios.post(`${POST_URL}?${query.toString()}`, req.fmsRawBody, {
      'Content-Type': 'application/json'
    });
    console.log(`remote: ${remoteAddr}: forwarded: ${req.body?.event} [${req.body?.payload?.object?.participant?.user_name}] status: ${responseGAS.status} response: ${responseGAS.data}`);

    if (!isEndpointValidation) {
      const contentType = responseGAS.headers['content-type'] || 'application/json';
      return (responseGAS.status >= 200 && responseGAS.status < 300)
        ? res.status(200).type(contentType).send(responseGAS.data)
        : res.status(502).type(contentType).send(responseGAS.data);
    }

    const hashedTokenGAS = responseGAS.data.encryptedToken;
    isForwardAllowed = (hashedToken === hashedTokenGAS);
    if (isForwardAllowed) {
      console.log(`remote: ${remoteAddr}: hashed token matched: ${hashedTokenGAS}`);
    } else {
      console.error(`remote: ${remoteAddr}: hashed token mismatch: ${hashedToken}(proxy), ${hashedTokenGAS}(GAS)`);
    }
  } catch (err) {
    console.error(`remote: ${remoteAddr}: ${req.body.event} failed: ${err.message}`);
    if (req.body.event !== 'endpoint.url_validation') {
      return res.status(502).send('proxy forwarding failed');
    }
  }
});

app.listen(PORT, () => {
  console.log(`Zoom Webhook server running on port ${PORT}`);
});

// end of file
