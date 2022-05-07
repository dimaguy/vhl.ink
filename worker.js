addEventListener('fetch', event => {
	const { request } = event;

	switch (request.method) {
		case 'POST':
			return event.respondWith(handlePOST(request).catch(err => {
				const message = err.reason || err.stack || 'Unknown Error';
		  
				return new Response(message, {
				  status: err.status || 500,
				  statusText: err.statusText || null,
				  headers: {
					'Content-Type': 'text/plain;charset=UTF-8',
					// Disables caching by default.
					'Cache-Control': 'no-store',
					// Returns the "Content-Length" header for HTTP HEAD requests.
					'Content-Length': message.length,
				},
			});
		}));
		case 'DELETE':
			return event.respondWith(handleDELETE(request).catch(err => {
				const message = err.reason || err.stack || 'Unknown Error';
		  
				return new Response(message, {
				  status: err.status || 500,
				  statusText: err.statusText || null,
				  headers: {
					'Content-Type': 'text/plain;charset=UTF-8',
					// Disables caching by default.
					'Cache-Control': 'no-store',
					// Returns the "Content-Length" header for HTTP HEAD requests.
					'Content-Length': message.length,
				},
			});
		}));
		default:
			return event.respondWith(handleRequest(request, event).catch(err => {
				const message = err.reason || err.stack || 'Unknown Error';
		  
				return new Response(message, {
				  status: err.status || 500,
				  statusText: err.statusText || null,
				  headers: {
					'Content-Type': 'text/plain;charset=UTF-8',
					// Disables caching by default.
					'Cache-Control': 'no-store',
					// Returns the "Content-Length" header for HTTP HEAD requests.
					'Content-Length': message.length,
				},
			});
		}));
	}
});

const html = `<!DOCTYPE html>
<body>
    <pre>
    use an actual path if you're trying to fetch something.
    send a POST request with form data "url" and "path" if you're trying to put something.
    Use HTTP Basic Auth for authentication.
    
    source: <a href="https://github.com/dimaguy/vhl.ink">dimaguy/vhl.ink</a>
    </pre>
	<form action="/" target="result" method="post">
	<label for="url">Link*:</label><br>
	<input type="text" id="url" name="url" value=""><br>
	<label for="path">Path:</label><br>
	<input type="text" id="path" name="path" value=""><br><br>
	<input type="submit" value="Shorten!"><br>
	<iframe src="about:blank" title="result"></iframe> 
	</form>
</body>`;

/**
 * Respond to POST requests with shortened URL creation
 * @param {Request} request
 */
async function handlePOST(request) {
	// The "Authorization" header is sent when authenticated.
	if (request.headers.has('Authorization')) {
        	// Throws exception when authorization fails.
        	const { user, pass } = basicAuthentication(request);
        	verifyCredentials(user, pass);

		const shortener = new URL(request.url);
		const data = await request.formData();
		const redirectURL = data.get('url');
		const path = data.get('path') || crypto.randomUUID().substring(0,4);
		if (!redirectURL || !path)
			return new Response('`url` must be set. optionally add a path', { status: 400 });
		// validate redirectURL is a URL
		try {
			new URL(redirectURL);
		} catch (e) {
			if (e instanceof TypeError) 
				return new Response('`url` needs to be a valid http url.', { status: 400 });
			else throw e;
		};

		// will overwrite current path if it exists
		await LINKS.put(path, redirectURL);
		return new Response(`${path}`, {
			status: 201,
		});
	}

	// Not authenticated.
	return new Response('You need to login.', {
		status: 401,
		headers: {
			// Prompts the user for credentials.
          		'WWW-Authenticate': 'Basic realm="s.linkpuff.me", charset="UTF-8"',
        	},
	});
}

/**
 * Respond to DELETE requests by deleting the shortlink
 * @param {Request} request
 */
async function handleDELETE(request) {
	// The "Authorization" header is sent when authenticated.
	if (request.headers.has('Authorization')) {
        	// Throws exception when authorization fails.
        	const { user, pass } = basicAuthentication(request);
        	verifyCredentials(user, pass);

		const url = new URL(request.url);
		const path = url.pathname.split('/')[1];
		if (!path) return new Response('Not found', { status: 404 });
		await LINKS.delete(path);
		return new Response(`${request.url} deleted!`, { status: 200 });
      }

      // Not authenticated.
	return new Response('You need to login.', {
		status: 401,
		headers: {
			// Prompts the user for credentials.
			'WWW-Authenticate': 'Basic realm="s.linkpuff.me", charset="UTF-8"',
		},
	});
}

/**
 * Respond to GET requests with redirects.
 *
 * Authenticated GET requests without a path will return a list of all
 * shortlinks registered with the service.
 * @param {Request} request
 */
async function handleRequest(request, event) {
	const url = new URL(request.url);
	const path = url.pathname.split('/')[1];
	// Return list of available shortlinks if user supplies admin credentials.

	if (!path) {
		// The "Authorization" header is sent when authenticated.
		if (request.headers.has('Authorization')) {
			// Throws exception when authorization fails.
			const { user, pass } = basicAuthentication(request);
			verifyCredentials(user, pass);
			// Only returns this response when no exception is thrown.
			const { keys } = await LINKS.list();
			let paths = "";
			keys.forEach(element => paths += `${element.name}\n`);
			return new Response(paths, { status: 200 });
		};
		// Not authenticated, but didn't try to authenticate
		return new Response(html, {
			headers: {
				'content-type': 'text/html;charset=UTF-8',
			},
		});
	}

	//ShareX support path
	if (path === 'delete') {
		// The "Authorization" header is sent when authenticated.
		if (request.headers.has('Authorization')) {
			// Throws exception when authorization fails.
			const { user, pass } = basicAuthentication(request);
			verifyCredentials(user, pass);
			// Only returns this response when no exception is thrown.
			const url = new URL(request.url);
			const path = url.pathname.split('/')[2];
			if (!path) return new Response('Not found', { status: 404 });
			await LINKS.delete(path);
			return new Response(`${request.url} deleted!`, { status: 200 });
		}

      // Not authenticated.
      return new Response('You need to login.', {
        status: 401,
        headers: {
          // Prompts the user for credentials.
          'WWW-Authenticate': 'Basic realm="s.linkpuff.me", charset="UTF-8"',
        },
      });

	}
	if (path === 'auth') {
		// The "Authorization" header is sent when authenticated.
		if (request.headers.has('Authorization')) {
			// Throws exception when authorization fails.
			const { user, pass } = basicAuthentication(request);
			verifyCredentials(user, pass);
			// Only returns this response when no exception is thrown.
			return new Response('You have private access.', {
				status: 200,
				headers: {
					'Cache-Control': 'no-store',
				},
			});
			}

			// Not authenticated.
			return new Response('You need to login.', {
				status: 401,
				headers: {
					// Prompts the user for credentials.
					'WWW-Authenticate': 'Basic realm="s.linkpuff.me", charset="UTF-8"',
				},
			});
	}
	/*
	if (path === 'quack') {
		const resObject = {
			text: 'You just got ducked 🦆',
			response_type: 'in_channel',
		};
	
		// Just hope it works lol
		await fetch(SLACK_WEBHOOK_QUACK, {
			method: 'POST',
			body: JSON.stringify(resObject),
			headers: { 'Content-Type': 'application/json' },
		});
	}*/

	const redirectURL = await LINKS.get(path);
	if (redirectURL) {
		const analyticsReq = {
			method: 'POST',
			body: JSON.stringify({ 'path': path }),
			headers: { 'Content-Type': 'application/json' },
		};
		//event.waitUntil(fetch(ANALYTICS_URL, analyticsReq));

		return Response.redirect(redirectURL, 302);
	}

	return new Response('URL not found. Sad!', { status: 404 });
}

/**
 * Throws exception on verification failure.
 * @param {string} user
 * @param {string} pass
 * @throws {UnauthorizedException}
 */
function verifyCredentials(user, pass) {
	/*
	if (BASIC_USER !== user) {
	throw new UnauthorizedException('Invalid username.');
	}*/
	if (SECRET_KEY !== pass) {
		//throw new Response('Unauthorized: Invalid password.', {status: 404})
		throw new UnauthorizedException('Invalid password.');
	}
}

/**
 * Parse HTTP Basic Authorization value.
 * @param {Request} request
 * @throws {BadRequestException}
 * @returns {{ user: string, pass: string }}
 */
function basicAuthentication(request) {
	const Authorization = request.headers.get('Authorization');

	const [scheme, encoded] = Authorization.split(' ');

	// The Authorization header must start with Basic, followed by a space.
	if (!encoded || scheme !== 'Basic') {
		throw new BadRequestException('Malformed authorization header.');
	}

	// Decodes the base64 value and performs unicode normalization.
	// @see https://datatracker.ietf.org/doc/html/rfc7613#section-3.3.2 (and #section-4.2.2)
	// @see https://dev.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String/normalize
	const buffer = Uint8Array.from(atob(encoded), character => character.charCodeAt(0));
	const decoded = new TextDecoder().decode(buffer).normalize();

	// The username & password are split by the first colon.
	//=> example: "username:password"
	const index = decoded.indexOf(':');

	// The user & password are split by the first colon and MUST NOT contain control characters.
	// @see https://tools.ietf.org/html/rfc5234#appendix-B.1 (=> "CTL = %x00-1F / %x7F")
	if (index === -1 || /[\0-\x1F\x7F]/.test(decoded)) {
		throw new BadRequestException('Invalid authorization value.');
	}

	return {
		user: decoded.substring(0, index),
		pass: decoded.substring(index + 1),
	};
}

function UnauthorizedException(reason) {
	this.status = 401;
	this.statusText = 'Unauthorized';
	this.reason = reason;
}

function BadRequestException(reason) {
	this.status = 400;
	this.statusText = 'Bad Request';
	this.reason = reason;
}

