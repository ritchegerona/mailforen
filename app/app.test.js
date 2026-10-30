'use strict';
/* Plain-Node smoke test for the analyzer's pure helpers. Prints OK and exits 0 on success. */
const assert = require('assert');
const {
  detectTarget, parseReceivedChain, parseAuthResults, parseSpf, parseDmarc,
  extractUrls, parseEml, detectTypoSquat, analyzeUrlHeuristics, editDistance
} = require('./app.js');

const EML = [
  'Received: from mail.example.com (mail.example.com [203.0.113.5])',
  '\tby mx.gmail.com with ESMTPS id 123;',
  '\tTue, 1 Oct 2026 10:00:00 +0000',
  'Received: from attacker.internal (unknown [192.168.1.10])',
  '\tby mail.example.com with SMTP id abc;',
  '\tTue, 1 Oct 2026 09:59:00 +0000',
  'Authentication-Results: mx.gmail.com;',
  '\tspf=softfail (domain owner discourages) smtp.mailfrom=example.com;',
  '\tdmarc=fail action=quarantine header.from=example.com;',
  '\tdkim=pass header.i=@example.com',
  'From: "PayPal" <support@paypa1.com>',
  'Reply-To: scammer@evil.xyz',
  'Return-Path: <bounce@evil.xyz>',
  'Date: Tue, 1 Oct 2026 09:58:00 +0000',
  'Message-ID: <20261001@example.com>',
  'Subject: Verify your account',
  '',
  'Click https://xn--aypayal-2ve.com/login now or http://203.0.113.9/pay via https://bit.ly/xyz'
].join('\n');

// target detection
assert.strictEqual(detectTarget('a.user+tag@gmail.com'), 'email');
assert.strictEqual(detectTarget('https://example.com/path?q=1'), 'url');
assert.strictEqual(detectTarget('example.co.uk'), 'domain');
assert.strictEqual(detectTarget('not a target!'), 'unknown');

// received chain: topmost header is the last hop; hop 1 = earliest
const hops = parseReceivedChain(EML);
assert.strictEqual(hops.length, 2);
assert.strictEqual(hops[0].by, 'mx.gmail.com');
assert.strictEqual(hops[0].hop, 2);
assert.strictEqual(hops[1].hop, 1);
assert.strictEqual(hops[1].from, 'attacker.internal');
assert.strictEqual(hops[1].with, 'SMTP');

// authentication-results
const auths = parseAuthResults(EML);
assert.strictEqual(auths.length, 1);
assert.strictEqual(auths[0].spf, 'softfail');
assert.strictEqual(auths[0].dmarc, 'fail');
assert.strictEqual(auths[0].dkim, 'pass');

// SPF parsing
assert.strictEqual(parseSpf('v=spf1 include:_spf.google.com +all').openAll, true);
assert.strictEqual(parseSpf('v=spf1 mx -all').openAll, false);
assert.strictEqual(parseSpf('v=spf1 mx ~all').openAll, false);
assert.strictEqual(parseSpf('v=spf1 mx ~all').allQualifier, '~');
assert.strictEqual(parseSpf('not spf'), null);

// DMARC parsing
assert.strictEqual(parseDmarc('v=DMARC1; p=none; rua=mailto:d@e.com').policy, 'none');
assert.strictEqual(parseDmarc('v=DMARC1; p=reject').policy, 'reject');
assert.strictEqual(parseDmarc('v=spf1'), null);

// typo-squat detection
const typo = detectTypoSquat('paypa1.com');
assert.ok(typo && typo.closest === 'paypal.com' && typo.distance === 1, 'paypa1.com flagged as paypal.com typo-squat');
assert.ok(detectTypoSquat('gmai1.com'), 'gmai1.com flagged');
assert.strictEqual(detectTypoSquat('gmail.com'), null, 'exact popular domain not flagged');
assert.strictEqual(editDistance('kitten', 'sitting'), 3);

// URL heuristics
const puny = analyzeUrlHeuristics('https://xn--aypayal-2ve.com/login');
assert.ok(puny.some(c => c.status === 'fail' && /punycode/i.test(c.title)), 'punycode flagged');
const ip = analyzeUrlHeuristics('http://203.0.113.9/pay');
assert.ok(ip.some(c => c.status === 'fail' && /IP literal/i.test(c.title)), 'IP host flagged');
assert.ok(ip.some(c => c.status === 'fail' && /Scheme/i.test(c.title)), 'http scheme flagged');
const short = analyzeUrlHeuristics('https://bit.ly/xyz');
assert.ok(short.some(c => c.status === 'warn' && /shortener/i.test(c.title)), 'shortener flagged');
const clean = analyzeUrlHeuristics('https://example.com/');
assert.ok(!clean.some(c => c.status === 'fail'), 'clean URL has no fails');

// URL extraction
const urls = extractUrls(EML);
assert.deepStrictEqual(urls, ['https://xn--aypayal-2ve.com/login', 'http://203.0.113.9/pay', 'https://bit.ly/xyz']);

// full eml parse
const eml = parseEml(EML, new Date('2026-10-30T00:00:00Z').getTime());
assert.strictEqual(eml.from.domain, 'paypa1.com');
assert.strictEqual(eml.replyTo.domain, 'evil.xyz');
assert.strictEqual(eml.returnPath.domain, 'evil.xyz');
assert.strictEqual(eml.messageIdDomain, 'example.com');
assert.strictEqual(eml.mismatchFromReplyTo, true);
assert.strictEqual(eml.mismatchFromReturnPath, true);
assert.strictEqual(eml.mismatchFromMessageId, true);
assert.strictEqual(eml.dateAgeDays, 29);
assert.strictEqual(eml.urls.length, 3);

console.log('OK');
