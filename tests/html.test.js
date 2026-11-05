import { test } from 'node:test';
import assert from 'node:assert/strict';
import { eachTag, attrsOf, parsePage, detectBuilder, wordpressVersion, libraries, thirdParties } from '../lib/html.js';
import { evaluate } from '../lib/checks.js';
import { site, STRONG, NOW } from './fixtures.js';

const names = (html) => [...eachTag(html)].map((t) => t.name);

test('the tag walker skips comments and the insides of scripts, styles and noscript', () => {
  assert.deepEqual(names('<!-- <img src=x> --><p>a</p><img src=y>'), ['p', 'img']);
  assert.deepEqual(names('<script>document.write("<iframe src=x></iframe>")</script><a>'), ['script', 'a']);
  assert.deepEqual(names('<SCRIPT>x</SCRIPT><STYLE>a{}</STYLE><b>'), ['script', 'style', 'b']);
  assert.deepEqual(names('<noscript><img src="http://t.example.net/p.gif"></noscript><i>'), ['noscript', 'i']);
  assert.deepEqual(names('1 < 2 and 3 <4 <5> </p> <b>'), ['b'], 'tag names start with a letter');
});

test('a ">" inside a quoted attribute does not end the tag', () => {
  const [t] = eachTag('<meta content="a > b" name="x"><p>');
  assert.equal(attrsOf(t.inner).content, 'a > b');
  assert.equal(attrsOf(t.inner).name, 'x');
});

test('attributes: any quoting, any case, the first duplicate wins', () => {
  assert.deepEqual({ ...attrsOf(` SRC=/a.js DEFER data-x='1' src="/b.js"`) }, { src: '/a.js', defer: '', 'data-x': '1' });
});

test('hostile pages cannot stall the scan: 256 KB of bait parses in well under a second', () => {
  const size = 262144;
  const bait = {
    'unclosed meta tags': '<meta '.repeat(size / 6),
    'unclosed quote': '<a "'.repeat(size / 4),
    'endless attributes': '<img ' + 'a=1 '.repeat(size / 4),
    'nested angle brackets': '<'.repeat(size),
    'script openers': '<script>'.repeat(size / 8),
    'comment openers': '<!--'.repeat(size / 4),
    'form tags': '<form action="http://x.example.net/">'.repeat(size / 37),
  };
  for (const [name, html] of Object.entries(bait)) {
    const t0 = performance.now();
    parsePage(html);
    const parsed = performance.now() - t0;
    assert.ok(parsed < 800, `${name}: parse took ${Math.round(parsed)} ms`);
    const t1 = performance.now();
    evaluate(site({ headers: STRONG, body: html }), { now: NOW });
    const graded = performance.now() - t1;
    assert.ok(graded < 800, `${name}: grading took ${Math.round(graded)} ms`);
  }
});

test('parsePage collects what the checks need', () => {
  const p = parsePage(`<html data-wf-site="1"><head>
    <meta name="Generator" content="WordPress 6.4.2">
    <meta http-equiv="content-security-policy" content="default-src 'self'">
    <link rel="stylesheet" href="http://a.example.net/s.css"><link rel="canonical" href="http://a.example.net/">
    <script src="http://a.example.net/a.js"></script><script src="/local.js"></script>
    <img src="http://a.example.net/i.png"><iframe src="https://b.example.net/f"></iframe>
    </head><body><form action="/x"><input type=PASSWORD></form></body></html>`);
  assert.equal(p.generator, 'WordPress 6.4.2');
  assert.equal(p.metaCsp, "default-src 'self'");
  assert.deepEqual(p.active.sort(), ['http://a.example.net/a.js', 'http://a.example.net/s.css']);
  assert.deepEqual(p.passive, ['http://a.example.net/i.png']);
  assert.deepEqual(p.scripts, ['http://a.example.net/a.js', '/local.js']);
  assert.deepEqual(p.frames, ['https://b.example.net/f']);
  assert.equal(p.forms.length, 1);
  assert.equal(p.hasPassword, true);
  assert.equal(p.webflow, true);
});

test('builders: found from the generator tag or from where their assets live', () => {
  const b = (html) => detectBuilder(parsePage(html));
  assert.equal(b('<meta name="generator" content="Wix.com Website Builder">'), 'wix');
  assert.equal(b('<script src="https://cdn.shopify.com/s/x.js"></script>'), 'shopify');
  assert.equal(b('<link rel="stylesheet" href="https://static1.squarespace.com/a.css">'), 'squarespace');
  assert.equal(b('<script src="/wp-content/themes/x/a.js"></script>'), 'wordpress');
  assert.equal(b('<p>hand-written</p>'), null);
});

test('WordPress version: the generator tag, else the core stylesheet, never a theme version', () => {
  const v = (html) => wordpressVersion(parsePage(html));
  assert.equal(v('<meta name="generator" content="WordPress 6.4.2">'), '6.4.2');
  assert.equal(v(`<link rel='stylesheet' href='https://x.example.net/wp-includes/css/dist/block-library/style.min.css?ver=6.5.3'>`), '6.5.3');
  assert.equal(v(`<link rel='stylesheet' href='https://x.example.net/wp-content/themes/t/style.css?ver=1.2.3'>`), null);
  assert.equal(v('<meta name="generator" content="Elementor 3.1.2">'), null);
});

test('libraries: reads versions from the usual CDN and file shapes', () => {
  const lib = (src) => libraries([src])[0];
  const cases = [
    ['https://code.jquery.com/jquery-1.12.4.min.js', 'jQuery', '1.12.4', true],
    ['https://code.jquery.com/jquery-3.7.1.slim.min.js', 'jQuery', '3.7.1', false],
    ['https://ajax.googleapis.com/ajax/libs/jquery/3.4.1/jquery.min.js', 'jQuery', '3.4.1', true],
    ['https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js', 'jQuery', '3.6.0', false],
    ['/wp-includes/js/jquery/jquery.min.js?ver=3.7.1', 'jQuery', '3.7.1', false],
    ['/wp-includes/js/jquery/jquery.js?ver=1.12.4', 'jQuery', '1.12.4', true],
    ['https://code.jquery.com/ui/1.12.1/jquery-ui.min.js', 'jQuery UI', '1.12.1', true],
    ['https://ajax.googleapis.com/ajax/libs/jqueryui/1.13.2/jquery-ui.min.js', 'jQuery UI', '1.13.2', false],
    ['https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.7/js/bootstrap.min.js', 'Bootstrap', '3.3.7', true],
    ['https://cdn.jsdelivr.net/npm/bootstrap@4.1.3/dist/js/bootstrap.bundle.min.js', 'Bootstrap', '4.1.3', true],
    ['https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.min.js', 'Bootstrap', '4.6.2', false],
    ['https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.min.js', 'Bootstrap', '5.3.0', false],
    ['https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/js/bootstrap.min.js', 'Bootstrap', '3.4.1', false],
    ['https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js', 'AngularJS', '1.8.2', true],
    ['https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.20/lodash.min.js', 'Lodash', '4.17.20', true],
    ['https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js', 'Lodash', '4.17.21', false],
  ];
  for (const [src, name, version, risky] of cases) {
    const l = lib(src);
    assert.ok(l, src);
    assert.deepEqual([l.name, l.version, l.risky], [name, version, risky], src);
  }
});

test('libraries: never guesses, so a look-alike or an unknown version says nothing', () => {
  const none = [
    '/js/jquery.min.js',                                                  // no version anywhere
    '/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.4.1',             // a different library
    '/wp-content/plugins/x/jquery.validate.min.js?ver=1.19.5',
    '/wp-content/themes/t/js/bootstrap.min.js?ver=1.0.2',                 // the theme's version, not Bootstrap's
    '/wp-content/themes/t/js/jquery.js?ver=2.0.0',
    'https://cdn.example.net/my-angular-app.js',
    'not a url at all %%%',
  ];
  assert.deepEqual(libraries(none), []);
});

test('third parties: named when known, by domain when not, and your own domain never counts', () => {
  const p = parsePage(`<script src="https://www.googletagmanager.com/gtm.js?id=x"></script>
    <script src="https://connect.facebook.net/en_US/fbevents.js"></script>
    <script src="//static.hotjar.com/c/hotjar.js"></script>
    <iframe src="https://www.youtube.com/embed/x"></iframe>
    <script src="https://cdn.unknownvendor.io/a.js"></script>
    <script src="https://cdn.shop.example.com/own.js"></script>
    <script src="/also-own.js"></script>`);
  assert.deepEqual(thirdParties(p, 'shop.example.com'), ['Google Tag Manager', 'Meta (Facebook)', 'Hotjar', 'unknownvendor.io', 'YouTube']);
});
