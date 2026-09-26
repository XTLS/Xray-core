// Run with: node --test transport/internet/browser_dialer/dialer_test.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { runInNewContext } from 'node:vm';

const html = readFileSync(new URL('./dialer.html', import.meta.url), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
const chunkSize = 64 * 1024;
const defaultChunks = 1024;
const readWindow = 4 * 1024 * 1024;

function startDownload({ consume = false, legacy = false, chunks = defaultChunks } = {}) {
	const sockets = [];
	let reads = 0;
	let canceled = false;
	let signal;
	class Socket {
		static OPEN = 1;
		readyState = 1;
		bufferedAmount = 0;
		messages = [];
		constructor() { sockets.push(this); }
		send(data) {
			this.messages.push(data);
			// Deliberately keep bufferedAmount at zero: TCP receipt does not mean
			// that the Xray application has consumed these bytes.
			if (consume && !legacy && typeof data !== 'string') {
				queueMicrotask(() => this.onmessage({ data: String(data.byteLength) }));
			}
		}
		close() {
			if (this.readyState === 3) return;
			this.readyState = 3;
			this.onclose?.({});
		}
	}
	const reader = {
		async read() {
			if (canceled || reads === chunks) return { done: true };
			const value = new Uint8Array(chunkSize).fill(reads % 251);
			reads++;
			return { done: false, value };
		},
		cancel() { canceled = true; return Promise.resolve(); },
	};
	const context = {
		window: { location: { host: '127.0.0.1' } },
		console: { log() {}, error() {} },
		WebSocket: Socket,
		AbortController,
		URL,
		setInterval() {},
		setTimeout() { assert.fail('download backpressure must not depend on timers'); },
		async fetch(_url, init) {
			signal = init.signal;
			return { body: { getReader: () => reader } };
		},
	};
	runInNewContext(script + '\ncheck();', context);
	const socket = sockets[0];
	socket.onmessage({ data: JSON.stringify({ method: 'GET', url: 'https://xray.test/', extra: {}, streamResponse: true, readWindow: legacy ? undefined : readWindow }) });
	return {
		socket,
		ack(bytes) { socket.onmessage({ data: String(bytes) }); },
		get reads() { return reads; },
		get canceled() { return canceled; },
		get aborted() { return signal?.aborted; },
		get activeDownloads() { return runInNewContext('upstreamGetCount', context); },
	};
}

// Flush promise continuations without depending on wall-clock timer scheduling.
async function settle() {
	for (let i = 0; i < 8192; i++) await Promise.resolve();
}

function assertPayload(socket) {
	const messages = socket.messages.filter(value => typeof value !== 'string');
	assert.equal(messages.length, defaultChunks);
	for (let i = 0; i < defaultChunks; i++) {
		assert.equal(messages[i].byteLength, chunkSize);
		assert.ok(messages[i].every(byte => byte === i % 251), `chunk ${i} changed`);
	}
}

test('a stalled receiver stops HTTP reads even after the WebSocket queue drains', async () => {
	const download = startDownload();
	await settle();
	assert.equal(download.reads * chunkSize, readWindow);
	assert.equal(download.socket.messages[0], 'ok-read');
	await settle();
	assert.equal(download.reads * chunkSize, readWindow);
	download.socket.close();
	await settle();
});

test('consumption acknowledgements resume the response without loss or reordering', async () => {
	const download = startDownload();
	await settle();
	let acknowledged = 0;
	while (download.activeDownloads) {
		const available = download.reads * chunkSize - acknowledged;
		assert.ok(available >= readWindow / 2);
		download.ack(readWindow / 2);
		acknowledged += readWindow / 2;
		await settle();
	}
	assertPayload(download.socket);
	assert.equal(download.socket.readyState, 3);
});

test('closing a paused download cancels HTTP and wakes the credit waiter', async () => {
	const download = startDownload();
	await settle();
	const reads = download.reads;
	download.socket.close();
	await settle();
	assert.equal(download.reads, reads);
	assert.equal(download.canceled, true);
	assert.equal(download.aborted, true);
	assert.equal(download.activeDownloads, 0);
});

test('EOF waits for the last required acknowledgement before closing', async () => {
	const chunks = readWindow / chunkSize - 1;
	const download = startDownload({ chunks });
	await settle();
	assert.equal(download.reads, chunks);
	assert.equal(download.activeDownloads, 1);
	download.ack(readWindow / 2);
	await settle();
	assert.equal(download.activeDownloads, 0);
	assert.equal(download.socket.readyState, 3);
});

test('a fast receiver transfers the full response without polling', async () => {
	const download = startDownload({ consume: true });
	await settle();
	assertPayload(download.socket);
	assert.equal(download.activeDownloads, 0);
});

test('tasks from an older core do not require acknowledgements', async () => {
	const download = startDownload({ legacy: true });
	await settle();
	assert.equal(download.socket.messages[0], 'ok');
	assertPayload(download.socket);
	assert.equal(download.activeDownloads, 0);
});

for (const credit of ['invalid', -1, 0, readWindow + 1, 0.5]) {
	test(`invalid consumption credit ${credit} closes the download`, async () => {
		const download = startDownload();
		await settle();
		download.ack(credit);
		await settle();
		assert.equal(download.canceled, true);
		assert.equal(download.activeDownloads, 0);
	});
}
