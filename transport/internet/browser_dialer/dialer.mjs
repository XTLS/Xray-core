// 2025 (C) Team Cloudchaser
// Licensed under MIT License

"use strict";

const FutureSignal = class FutureSignal {
	#trueResolve;
	finished = false;
	onfinish;
	constructor() {
		let upThis = this;
		upThis.onfinish = new Promise((p) => {
			upThis.#trueResolve = p;
		});
	};
	resolve() {
		this.finished = true;
		this.#trueResolve();
	};
};
const denoClient = self.Deno?.createHttpClient({
	"allowHost": true
});

export default class AppatDialer {
	report = true; // Set to false to disable response status reporting
	instanceId;
	#wsNext = true; // Set to true to trigger WS fallback
	#rqNext = true; // Set to true to trigger fetch fallback
	#isBrowser = 2; // 2 for half duplex browser, 1 for full duplex, 0 for non-browser
	#prefix;
	#csrf;
	#compiledPrefix;
	#compiledWsPrefix;
	#controller;
	#aborter;
	#uploader = new Map();
	#uploadDeny = new Set();
	constructor(prefix, csrf) {
		if (!Request.prototype.hasOwnProperty("body")) {
			this.#rqNext = false;
			throw(new Error("Fetch requests do not support streamable bodies"));
		};
		if (typeof self?.WebSocketStream !== "function") {
			this.#wsNext = false;
			throw(new Error("WebSocket does not support streaming"));
		};
		if (typeof self?.Deno !== "undefined") {
			this.#isBrowser = 0;
		};
		this.#csrf = csrf;
		this.#prefix = prefix;
	};
	async start() {
		let upThis = this;
		if (upThis.#controller) {
			switch (upThis.#controller.readyState) {
				case WebSocket.CLOSING:
				case WebSocket.CLOSED: {
					throw(new Error(`Attempted reconnection for an active dialer`));
					break;
				};
			};
		};
		// Generate a new page ID
		upThis.instanceId = self.crypto?.randomUUID();
		upThis.#compiledPrefix = `${upThis.#prefix}/ws/${upThis.instanceId}`;
		upThis.#compiledWsPrefix = upThis.#compiledPrefix.replace("http", "ws");
		upThis.#controller = new WebSocket(`${upThis.#compiledPrefix}/ctrl?token=${upThis.#csrf}`);
		upThis.#controller.addEventListener("error", (ev) => {
			console.warn(`Control socket has errored out:`, ev.error);
		});
		upThis.#controller.addEventListener("close", (ev) => {
			console.warn(`Control socket closed.`);
			upThis.#aborter?.abort();
		});
		upThis.#controller.addEventListener("opened", (ev) => {
			console.warn(`Control socket is now ready.`);
			upThis.#aborter = new AbortController();
		});
		upThis.#controller.addEventListener("message", async (ev) => {
			let data = JSON.parse(ev.data);
			console.debug(data);
			switch (data.m) {
				case "PING": {
					console.debug(`Pong!`);
					break;
				};
				case "APPAT": {
					switch (data.e?.appat) {
						case "requestEnd": {
							if (upThis.#uploader.has(data.c)) {
								upThis.#uploader.get(data.c)[2]();
								console.info(`Closed an ongoing upload.`);
							} else {
								upThis.#uploadDeny.add(data.c);
								console.info(`Closed a future upload.`);
							};
							break;
						};
					};
					break;
				};
				case "WS": {
					break;
				};
				case "WT": {
					break;
				};
				case "HEAD":
				case "GET":
				case "POST":
				case "PUT":
				case "DELETE":
				case "OPTIONS":
				case "PATCH": {
					let opt = {
						"method": data.m,
						"signal": upThis.#aborter
					};
					if (data.hasOwnProperty("e")) {
						if (data.e.hasOwnProperty("r")) {
							opt.referrerPolicy = "unsafe-url";
							// Would this change when web safety gets disabled?
							let rUrl = new URL(data.e.r);
							opt.referrer = data.e.r.replace(`${rUrl.protocol}//${rUrl.hostname}`, "");
						};
						if (data.e.hasOwnProperty("h")) {
							opt.headers = data.e.h;
						};
					};
					try {
						let wsStream = new WebSocketStream(`${upThis.#compiledWsPrefix}/${data.c}?token=${upThis.#csrf}`);
						let wssTun = await wsStream.opened;
						switch (data.m) {
							case "POST":
							case "PUT":
							case "DELETE":
							case "OPTIONS":
							case "PATCH": {
								// Add the request body
								let sourceReader = wssTun.readable.getReader();
								opt.body = new ReadableStream({
									"queueingStrategy": new ByteLengthQueuingStrategy({
										"highWaterMark": 65536
									}),
									"start": async (controller) => {
										upThis.#uploader.set(data.c, [
											controller,
											sourceReader,
											() => {
												controller.close();
												upThis.#uploader.delete(data.c);
											}
										])
									},
									"pull": async (controller) => {
										if (upThis.#uploadDeny.has(data.c)) {
											upThis.#uploader.get(data.c)[2]();
											upThis.#uploadDeny.delete(data.c);
										} else if (upThis.#uploader.has(data.c)) {
											// Only pipe when still active
											let {value, done} = await sourceReader.read();
											if (value !== undefined) {
												controller.enqueue(value);
											};
											if (done || upThis.#uploadDeny.has(data.c)) {
												upThis.#uploader.get(data.c)[2]();
												upThis.#uploadDeny.delete(data.c);
											};
										};
									}
								});
								if (upThis.#isBrowser > 1) {
									opt.duplex = "half";
									upThis.#controller.send(`{"c":"${data.c}","s":1,"t":"AppatError","e":"appat.halfDuplex"}`);
								} else {
									opt.duplex = "full";
								};
								break;
							};
						};
						if (denoClient) {
							opt.client = denoClient;
						};
						let req = await fetch(data.u, opt);
						if (upThis.report) {
							let report = {
								"c": data.c,
								"s": req.status,
								"t": req.statusText,
								"h": {}
							};
							for (const [k, v] of req.headers.entries()) {
								report.h[k] = v;
							};
							upThis.#controller.send(JSON.stringify(report));
						};
						if (data.m === "HEAD") {
							wssTun.close();
						} else {
							await req.body.pipeTo(wssTun.writable);
						};
					} catch (err) {
						console.warn(err);
						if (upThis.report) {
							let report = {
								"c": data.c,
								"s": 0,
								"t": err.name,
								"e": `${err.message}\n${err.stack}`
							};
							upThis.#controller.send(JSON.stringify(report));
						};
					};
					break;
				};
				default: {
					console.warn(`Unsupported method: ${data.m}`);
				};
			};
		});
	};
};
