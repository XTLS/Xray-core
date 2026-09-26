// Optional real-browser measurement harness; see README.md in this directory.
const { chromium } = require(process.env.XRAY_PLAYWRIGHT_MODULE || 'playwright');
const { spawn } = require('node:child_process');
const { createInterface } = require('node:readline');
const { createHash } = require('node:crypto');
const path = require('node:path');

const [html, mode = 'stall', sizeString = '268435456'] = process.argv.slice(2);
const size = Number(sizeString);
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

(async () => {
	const executable = process.env.XRAY_BROWSER_TEST_SERVER || path.join(__dirname, 'server');
	const child = spawn(executable, [
		'-html', path.resolve(html), '-bytes', String(size),
		'-legacy=' + String(process.env.XRAY_BROWSER_TEST_LEGACY === '1'),
	], { stdio: ['pipe', 'pipe', 'inherit'] });
	let browser;
	try {
		const lines = createInterface({ input: child.stdout });
		const url = await new Promise((resolve, reject) => {
			lines.once('line', resolve);
			child.once('error', reject);
			child.once('exit', code => reject(new Error(`test server exited: ${code}`)));
		});
		browser = await chromium.launch({
			executablePath: process.env.XRAY_BROWSER_TEST_EXECUTABLE,
			headless: true,
			ignoreDefaultArgs: [
				'--disable-background-timer-throttling',
				'--disable-backgrounding-occluded-windows',
				'--disable-renderer-backgrounding',
			],
		});
		// The only HTTPS endpoint is the loopback httptest server.
		const context = await browser.newContext({ ignoreHTTPSErrors: true });
		const page = await context.newPage();
		const errors = [];
		page.on('pageerror', error => errors.push(error.message));
		await page.addInitScript(() => {
			window.measure = { maxQueued: 0, sentBytes: 0, sockets: [] };
			const send = WebSocket.prototype.send;
			WebSocket.prototype.send = function (data) {
				if (!measure.sockets.includes(this)) measure.sockets.push(this);
				send.call(this, data);
				if (typeof data !== 'string') measure.sentBytes += data.byteLength;
				measure.maxQueued = Math.max(measure.maxQueued, this.bufferedAmount);
			};
		});
		await page.goto(url);
		const metrics = async () => fetch(url + '/metrics').then(response => response.json());
		const deadline = Date.now() + 10000;
		while (!(await metrics()).gets) {
			if (Date.now() > deadline) throw new Error('GET did not start');
			await sleep(20);
		}
		const start = Date.now();
		const samples = [];
		if (mode !== 'fast') {
			for (let i = 0; i < 3; i++) {
				await sleep(1000);
				samples.push({
					...await metrics(),
					browser: await page.evaluate(() => ({
						maxQueued: measure.maxQueued,
						sentBytes: measure.sentBytes,
						queued: measure.sockets.map(socket => socket.bufferedAmount),
					})),
				});
			}
		}
		if (mode === 'stall') {
			await fetch(url + '/abort');
			await sleep(200);
		} else {
			await fetch(url + '/resume');
			const timeout = Date.now() + 20000;
			while (!(await metrics()).complete) {
				if (Date.now() > timeout) throw new Error('transfer did not finish');
				await sleep(20);
			}
		}
		const result = await metrics();
		const elapsedMs = Date.now() - start;
		const visibility = await page.evaluate(() => document.visibilityState);
		const hash = createHash('sha256');
		const block = Buffer.alloc(65536);
		for (let i = 0; i < block.length; i++) block[i] = i & 255;
		for (let offset = 0; offset < size; offset += block.length) {
			hash.update(block.subarray(0, Math.min(block.length, size - offset)));
		}
		const expectedHash = hash.digest('hex');
		if (result.httpMajor !== 2) throw new Error('HTTP/2 was not negotiated');
		if (mode !== 'stall' && (result.receivedBytes !== size || result.hash !== expectedHash)) {
			throw new Error('payload mismatch');
		}
		if (errors.length) throw new Error(errors.join('\n'));
		console.log(JSON.stringify({
			html, mode, size, browser: browser.version(), elapsedMs, visibility,
			samples, result, expectedHash, errors,
		}));
	} finally {
		await browser?.close();
		child.stdin.end();
		child.kill();
	}
})().catch(error => {
	console.error(error);
	process.exitCode = 1;
});
