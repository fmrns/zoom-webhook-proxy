//  -*- coding: utf-8 -*-
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

const TIMESTAMP_TOLERANCE_SECONDS = 30;
const ZOOM_SECRET = '...';
const SIGNATURE_KEY = 'http_x_zm_signature';
const TIMESTAMP_KEY = 'http_x_zm_request_timestamp';

/**
 * @param {string} name
 * @returns {GoogleAppsScript.Spreadsheet.Sheet}
 */
function getSheet(name) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  let sheet = ss.getSheetByName(name);
  if (!sheet) {
    sheet = ss.insertSheet(name);
    const headers = ['name'];
    for (let i = 1; i <= 10; i++) {
      headers.push(`uuid ${i}`, `public IP ${i}`, `join${i}`, `private IP ${i}`, `leave${i}`);
    }
    sheet.appendRow(headers);
  }
  return sheet;
}

/**
 * @param {string} signature
 * @param {string} timestamp
 * @param {string} body
 * @returns {boolean}
 */
function is_valid_signature(signature, timestamp, body) {
  const hashedBody = Utilities
    .computeHmacSha256Signature(`v0:${timestamp}:${body}`, ZOOM_SECRET, Utilities.Charset.UTF_8)
    .map(b => (b & 0xFF).toString(16).padStart(2, '0'))
    .join('');
  return signature === ('v0=' + hashedBody);
}

function doPost(e) {
  const nw = new Date().getTime() / 1000;
  const trimmedFields = {
    [SIGNATURE_KEY]: e.parameter[SIGNATURE_KEY],
    [TIMESTAMP_KEY]: e.parameter[TIMESTAMP_KEY]
  }
  return handlePost(e.postData.contents, trimmedFields, nw)
}

function handlePost(contents, http_header = null, nw = null) {
  const zoomWebhook = JSON.parse(contents);
  const signatureValue = http_header?.[SIGNATURE_KEY] || null;
  const timestampValue = http_header?.[TIMESTAMP_KEY] || null;
  const timestampInt = timestampValue ? parseInt(timestampValue, 10) : -1;

  if (nw && (timestampInt < nw - TIMESTAMP_TOLERANCE_SECONDS || timestampInt > nw)) {
    return ContentService
      .createTextOutput(`invalid timestamp: ${timestampInt}, now:${nw}`)
      .setMimeType(ContentService.MimeType.TEXT);
  }

  if (zoomWebhook.event === 'endpoint.url_validation') {
    // ******************************************************
    // this logic produces a valid response, but Zoom does
    // NOT accept it due to redirection and latency issues.
    // It is intended exclusively for closed communication
    // between the proxy and GAS, such as internal checks
    // initiated by the proxy itself.
    // ******************************************************
    const plainToken = zoomWebhook.payload.plainToken;
    const hashedToken = Utilities
      .computeHmacSha256Signature(plainToken, ZOOM_SECRET, Utilities.Charset.UTF_8)
      .map(b => (b & 0xFF).toString(16).padStart(2, '0'))
      .join('');
    const response_body = {
      plainToken: plainToken,
      encryptedToken: hashedToken
    };
    return ContentService
      .createTextOutput(JSON.stringify(response_body))
      .setMimeType(ContentService.MimeType.JSON);
  }

  const participation_timestamp = new Date(
       zoomWebhook.payload.object.participant.join_time
    || zoomWebhook.payload.object.participant.leave_time);
  const log = getSheet('log');
  log.appendRow([
    participation_timestamp,
    zoomWebhook.payload.object.id, zoomWebhook.event,
    JSON.stringify(zoomWebhook) ]);

  if (http_header && !is_valid_signature(signatureValue, timestampValue, contents)){
    log.appendRow([ new Date(), 'invalid signature',
      http_header[SIGNATURE_KEY], http_header[TIMESTAMP_KEY] ]);
    return ContentService
      .createTextOutput('invalid signature')
      .setMimeType(ContentService.MimeType.TEXT);
  }

  // *******************
  // write your own app.
  // *******************

  const meetingId = zoomWebhook.payload.object.id.toString();

  const participant = zoomWebhook.payload.object.participant;
  const userName = participant.user_name;
  const uuid = participant.participant_uuid;

  const dateStr = Utilities
    .formatDate(participation_timestamp, Session.getScriptTimeZone(), 'yyyy-MM-dd');
  const sheetName = `${meetingId} - ${dateStr}`;

  const sheet = getSheet(sheetName);
  const data = sheet.getDataRange().getValues();
  let rowIndex = data.findIndex(row => row.includes(uuid));
  if (rowIndex === -1) {
    rowIndex = data.findIndex(row => row[0] === userName);
  }
  if (rowIndex === -1) {
    sheet.appendRow([ userName ]);
    rowIndex = sheet.getLastRow() - 1;
  }

  const rowValues = sheet.getRange(rowIndex + 1, 1, 1, sheet.getMaxColumns()).getValues()[0];
  if (zoomWebhook.event === 'meeting.participant_joined') {
    const join_time = new Date(participant.join_time)
    for (let i = 1; i < rowValues.length; i += 5) {
      const t1 = rowValues[i+2] ? rowValues[i+2].getTime() : 0;
      if (!isNaN(t1) && t1 === join_time.getTime()) {
        break;
      } else if (!rowValues[i] && !rowValues[i+1] && !rowValues[i+2] && !rowValues[i+3] && !rowValues[i+4]) {
        sheet.getRange(rowIndex + 1, i + 1).setValue(uuid);
        sheet.getRange(rowIndex + 1, i + 2).setValue(participant.public_ip);
        let cell = sheet.getRange(rowIndex + 1, i + 3);
        cell.setValue(join_time);
        cell.setNumberFormat('yyyy-mm-dd hh:mm:ss');
        break;
      }
    }
  } else if (zoomWebhook.event === 'meeting.participant_left') {
    const leave_time = new Date(participant.leave_time);
    for (let i = 1; i < rowValues.length; i += 5) {
      const t1 = rowValues[i+4] ? rowValues[i+4].getTime() : 0;
      if (!isNaN(t1) && t1 === leave_time.getTime()) {
        break;
      } else if (!rowValues[i+3] && !rowValues[i+4] &&
          (   (rowValues[i] === uuid && rowValues[i+1] && rowValues[i+2].getTime() < leave_time.getTime())
           || (!rowValues[i] && !rowValues[i+1] && !rowValues[i+2]))) {
        sheet.getRange(rowIndex + 1, i + 4).setValue(participant.private_ip);
        let cell = sheet.getRange(rowIndex + 1, i + 5);
        cell.setValue(leave_time);
        cell.setNumberFormat('yyyy-mm-dd hh:mm:ss');
        break;
      }
    }
  } else {
    log.appendRow([ new Date(), `unknown event: ${zoomWebhook.event}` ]);
    return ContentService
      .createTextOutput(`unknown event: ${zoomWebhook.event}`)
      .setMimeType(ContentService.MimeType.TEXT);
  }

  return ContentService.createTextOutput('OK maybe').setMimeType(ContentService.MimeType.TEXT);
}

function doGet(e) {
  return HtmlService.createHtmlOutput(`<html />`);
}

// end of file
