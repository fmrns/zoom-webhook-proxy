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

const app = express();
const PORT = process.env.PORT || 3000;
const ZOOM_SECRET = process.env.ZOOM_SECRET;
const POST_URL = process.env.POST_URL; // "https://script.google.com/macros/s/.../exec

//app.use(bodyParser.json());
app.use(bodyParser.json({
  verify: (req, res, buf) => {
    req.fmsRawBody = buf.toString('utf8');
  }
}));

app.post('/zoom-webhook-proxy', async (req, res) => {
  const signatureField = req.headers['x-zm-signature'];
  const timestampField = req.headers['x-zm-request-timestamp'];

  if (req.body.event === 'endpoint.url_validation') {
    const plainToken = req.body.payload.plainToken;
    const hashedToken = crypto
      .createHmac('sha256', ZOOM_SECRET)
      .update(plainToken).digest('hex');
    const response_body = {
      plainToken,
      encryptedToken: hashedToken
    };
    return res.status(200).json(response_body);

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
  //const message = `v0:${timestampField}:${JSON.stringify(req.body)}`;
  const message = `v0:${timestampField}:${req.fmsRawBody}`;
  const hash = crypto
    .createHmac('sha256', ZOOM_SECRET)
    .update(message)
    .digest('hex');
  const expectedSignature = `v0=${hash}`;

  if (signatureField !== expectedSignature) {
    console.warn('invalid signature.');
    return res.status(403).send('Invalid signature');
  }
  res.status(200).send('OK');

  // proxy
  console.log('Zoom Event:', req.body.event);
  const responseGAS = await axios.post(POST_URL, req.body);
});

app.listen(PORT, () => {
  console.log(`Zoom Webhook server running on port ${PORT}`);
});

// end of file
