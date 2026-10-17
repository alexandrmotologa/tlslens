import puppeteer from 'puppeteer';
import path from 'path';
import fs from 'fs';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const targetDir = path.resolve(__dirname, '../../docs/images');
const framesDir = path.resolve(__dirname, '../../docs/images/frames');
if (!fs.existsSync(targetDir)) fs.mkdirSync(targetDir, { recursive: true });
if (!fs.existsSync(framesDir)) fs.mkdirSync(framesDir, { recursive: true });

async function run() {
  console.log('Launching browser...');
  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--window-size=1440,900'],
  });

  const page = await browser.newPage();
  await page.setViewport({ width: 1440, height: 900, deviceScaleFactor: 2 });

  console.log('Navigating to TLSLens Studio...');
  await page.goto('http://localhost:8089', { waitUntil: 'networkidle0' });

  // 1. Ensure CA is initialized & issue leaf
  await page.evaluate(async () => {
    try {
      await fetch('/api/ca/init', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          commonName: 'TLSLens Local Development Root CA',
          organization: 'TLSLens PKI Studio',
          country: 'US',
          keyType: 'ecdsa',
          validityDays: 3650
        })
      });
      await fetch('/api/ca/issue', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          commonName: 'api.local.test',
          domains: ['api.local.test', '*.local.test', 'localhost'],
          ips: ['127.0.0.1', '::1'],
          validityDays: 365,
          keyType: 'ecdsa'
        })
      });
    } catch (e) {
      console.error(e);
    }
  });

  await page.reload({ waitUntil: 'networkidle0' });
  await new Promise((r) => setTimeout(r, 1000));

  console.log('Capturing CA Studio (tlslens-3.png)...');
  await page.screenshot({ path: path.join(targetDir, 'tlslens-3.png'), fullPage: false });

  // 2. Handshake Waterfall
  console.log('Navigating to Handshake Waterfall...');
  const buttons = await page.$$('button');
  for (const btn of buttons) {
    const text = await page.evaluate(el => el.textContent, btn);
    if (text && text.includes('Handshake Waterfall')) {
      await btn.click();
      break;
    }
  }
  await new Promise((r) => setTimeout(r, 500));

  // Click Run Probe
  const probeButtons = await page.$$('button');
  for (const btn of probeButtons) {
    const text = await page.evaluate(el => el.textContent, btn);
    if (text && text.includes('Run Probe')) {
      await btn.click();
      break;
    }
  }
  await new Promise((r) => setTimeout(r, 2000));
  console.log('Capturing Handshake Waterfall (tlslens-1.png)...');
  await page.screenshot({ path: path.join(targetDir, 'tlslens-1.png'), fullPage: false });

  // 3. Certificate Chain
  console.log('Navigating to Certificate Chain...');
  const chainButtons = await page.$$('button');
  for (const btn of chainButtons) {
    const text = await page.evaluate(el => el.textContent, btn);
    if (text && text.includes('Certificate Chain')) {
      await btn.click();
      break;
    }
  }
  await new Promise((r) => setTimeout(r, 500));

  const traceButtons = await page.$$('button');
  for (const btn of traceButtons) {
    const text = await page.evaluate(el => el.textContent, btn);
    if (text && text.includes('Trace Chain')) {
      await btn.click();
      break;
    }
  }
  await new Promise((r) => setTimeout(r, 2000));
  console.log('Capturing Certificate Chain (tlslens-2.png)...');
  await page.screenshot({ path: path.join(targetDir, 'tlslens-2.png'), fullPage: false });

  // 4. mTLS Playground
  console.log('Navigating to mTLS Playground...');
  const mtlsButtons = await page.$$('button');
  for (const btn of mtlsButtons) {
    const text = await page.evaluate(el => el.textContent, btn);
    if (text && text.includes('mTLS Playground')) {
      await btn.click();
      break;
    }
  }
  await new Promise((r) => setTimeout(r, 500));

  // Start Server
  const startButtons = await page.$$('button');
  for (const btn of startButtons) {
    const text = await page.evaluate(el => el.textContent, btn);
    if (text && text.includes('Start Server')) {
      await btn.click();
      break;
    }
  }
  await new Promise((r) => setTimeout(r, 1000));

  // Execute Handshake Probe
  const executeButtons = await page.$$('button');
  for (const btn of executeButtons) {
    const text = await page.evaluate(el => el.textContent, btn);
    if (text && text.includes('Execute Handshake Probe')) {
      await btn.click();
      break;
    }
  }
  await new Promise((r) => setTimeout(r, 2000));
  console.log('Capturing mTLS Playground (tlslens-4.png)...');
  await page.screenshot({ path: path.join(targetDir, 'tlslens-4.png'), fullPage: false });

  // 5. Capture sequence of frames for animated demo GIF
  console.log('Recording frames for tlslens_demo.gif...');
  const tabs = [
    'CA Studio',
    'Handshake Waterfall',
    'Certificate Chain',
    'TLS Diff',
    'Client Matrix',
    'mTLS Playground',
    'Security Audit',
    'Configs & K8s',
    'Domain Watcher',
    'ACME Server'
  ];
  let frameIdx = 0;

  for (const tabName of tabs) {
    const allBtns = await page.$$('button');
    for (const b of allBtns) {
      const text = await page.evaluate(el => el.textContent, b);
      if (text && text.includes(tabName)) {
        await b.click();
        break;
      }
    }
    await new Promise((r) => setTimeout(r, 800));

    // Capture 3 frames per tab
    for (let f = 0; f < 3; f++) {
      const framePath = path.join(framesDir, `frame_${String(frameIdx).padStart(4, '0')}.png`);
      await page.screenshot({ path: framePath, fullPage: false });
      frameIdx++;
      await new Promise((r) => setTimeout(r, 200));
    }
  }

  await browser.close();
  console.log(`Captured ${frameIdx} frames. Generating GIF with ffmpeg...`);

  const gifPath = path.join(targetDir, 'tlslens_demo.gif');
  // Use ffmpeg with high-quality color palette
  const palettePath = path.join(framesDir, 'palette.png');
  execSync(`ffmpeg -y -framerate 2 -i "${framesDir}/frame_%04d.png" -vf "fps=2,scale=1280:-1:flags=lanczos,palettegen" "${palettePath}"`, { stdio: 'inherit' });
  execSync(`ffmpeg -y -framerate 2 -i "${framesDir}/frame_%04d.png" -i "${palettePath}" -filter_complex "fps=2,scale=1280:-1:flags=lanczos[x];[x][1:v]paletteuse=dither=bayer:bayer_scale=3" "${gifPath}"`, { stdio: 'inherit' });

  // Cleanup frames
  fs.rmSync(framesDir, { recursive: true, force: true });
  console.log('Successfully generated screenshots and tlslens_demo.gif!');
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
