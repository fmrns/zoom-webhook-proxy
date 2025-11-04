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

require('dotenv').config();
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
const cidrList = process.env.REMOTE_CIDR_LIST
  .split(',')
  .map(c => new cidr(c.trim()));


/**
 * @param {string} ip
 * @param {cidr[]} cidrList
 * @returns {boolean}
 */
function is_ip_in(ip, cidrList) {
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
function is_valid_signature(signature, timestamp, body) {
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
  verify: (req, res, buf) => {
    req.fmsRawBody = buf.toString('utf8');
  }
}));

app.post('/zoom-webhook-proxy', async (req, res) => {
  const nw = new Date().getTime() / 1000;

  let remoteAddr = req.ip || req.connection.remoteAddress;
  console.info(`remote: ${remoteAddr}`);
  if (!is_ip_in(remoteAddr, cidrList)) {
    console.warn(`invalid remote: ${remoteAddr}`);
    return res.status(403).send('IP not allowed');
  }

  const signatureValue = req.headers?.[SIGNATURE_KEY] || null;
  const timestampValue = req.headers?.[TIMESTAMP_KEY] || null;
  const timestampInt = timestampValue ? parseInt(timestampValue, 10) : -1;

  if (timestampInt < nw - TIMESTAMP_TOLERANCE_SEC || timestampInt > nw) {
    console.warn(`invalid timestamp: ${timestampInt} now: ${nw}`);
    return res.status(403).send('invalid timestamp');
  }

  if (req.body.event === 'endpoint.url_validation') {
    const plainToken = req.body.payload.plainToken;
    const hashedToken = crypto
      .createHmac('sha256', ZOOM_SECRET)
      .update(plainToken).digest('hex');
    const responseBody = {
      plainToken,
      encryptedToken: hashedToken
    };
    return res.status(200).json(responseBody);

    // *********************************************************
    // validation requires an immediate response. the proxy must
    // respond directly instead of forwarding to the destination.
    // *********************************************************
    //const responseGAS = await axios.post(POST_URL, {
    //    event: 'endpoint.url_validation',
    //    payload: { plainToken }
    //});
    //const hashedTokenGAS = responseGAS.data.encryptedToken;
    //console.log('response(GAS): ', responseGAS.data);
    //console.log('hashed token(GAS): ', hashedTokenGAS);
    //return res.status(200).json(responseGAS.data);
  }

  // avoid re-serializing... cf. JCS
  // xxx `v0:${timestampValue}:${JSON.stringify(req.body)}`;
  if (!is_valid_signature(signatureValue, timestampValue, req.fmsRawBody)) {
    console.warn('invalid signature.');
    return res.status(403).send('invalid signature');
  }
  res.status(200).send('OK');

  try {
    console.log('forwarding event: ', req.body.event);
    const query = new URLSearchParams({
      http_x_zm_signature: signatureValue,
      http_x_zm_request_timestamp: timestampValue
    });
    const responseGAS = await axios.post(`${POST_URL}?${query.toString()}`, req.fmsRawBody, {
      'Content-Type': 'application/json'
    });
    console.log('forwarded: ', responseGAS.status);
    console.log(responseGAS.data);
  } catch (err) {
    console.error('failed: ', err.message);
  }
});

app.listen(PORT, () => {
  console.log(`Zoom Webhook server running on port ${PORT}`);
});

// end of file
