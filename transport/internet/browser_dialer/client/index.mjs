// 2025 (C) Team Cloudchaser
// Licensed under MIT License

"use strict";

import AppatController from "../dialer/index.mjs";

let pagePrefix;
if (self.location?.href) {
	pagePrefix = `${location.protocol}//${location.host}`;
} else if (self.Deno?.args[0]?.length > 0) {
	pagePrefix = `http://${self.Deno.args[0]}`;
} else {
	// Port 5779 should never be used for browser dialer controllers
	pagePrefix = `http://127.0.0.1:5779`;
};
console.debug(`Received dialer prefix: ${pagePrefix}`);

const nullCSRF = atob("X19DU1JGX1RPS0VOX18");
let pageCSRF = "__CSRF_TOKEN__"; // Replaced with a valid token dynamically
if (pageCSRF === nullCSRF) {
	// The CSRF token must be a valid UUID
	if (self.location?.search?.indexOf("?token=") === 0) {
		// Only a single query parameter is expected
		pageCSRF = self.location.search.substring(7);
	} else if (self.Deno?.args[1]?.length > 0) {
		pageCSRF = self.Deno.args[1];
	} else {
		pageCSRF = "00000000-0000-0000-0000-000000000000";
	};
};
console.debug(`Received CSRF token: ${pageCSRF}`);

let dialer = new AppatController(pagePrefix, pageCSRF);
dialer.start();
