// Dependencies
const proxy = require('http-proxy');
const https = require('https');
const http = require('http');
const crypto = require('crypto');
const assert = require('assert');
const zlib = require('zlib');
const { URL } = require('url');

// --- Manual constants (Unchanged) ---
const ALLOWED_METHODS = http.METHODS;
const ALLOWED_PROTOS = ['http', 'https'];
const ALLOWED_GZIP_METHODS = ['transform', 'decode', 'append']; // Note: 'append' mode might still be problematic with gzip
const DEFAULT_PROTO = 'https';
const DEFAULT_USERAGENT = 'Mozilla';

const getHosts = (hosts) => {
  if (!hosts) {
    return [];
  }
  let parsed = [];
  hosts = hosts.split(',');
  for (let i = 0; i < hosts.length; i++) {
    const host = hosts[i];
    try {
      // Basic validation if host looks okay
      if (!host || typeof host !== 'string' || host.includes('/') || host.includes(':')) {
           throw new Error(`Invalid host format: ${host}`);
      }
      new URL(`${DEFAULT_PROTO}://${host}`); // Validate if it can be part of a URL
    } catch (e) {
      // Log the specific host causing the error
      console.error(`Configuration error! Invalid host domain format on item: "${host}"`, e.message);
      throw new Error(`Configuration error! Invalid host domain format on item "${host}"`);
    }
    parsed.push({
      host: host.trim() // Trim whitespace
    });
  }
  return parsed;
};
// --- Environment Constants (Unchanged) ---
const PORT = process.env.PORT || 80;
const ACCESS_KEY = process.env.ACCESS_KEY && Buffer.from(process.env.ACCESS_KEY);
const USE_WHITELIST = process.env.USE_WHITELIST === 'true';
const USE_OVERRIDE_STATUS = process.env.USE_OVERRIDE_STATUS === 'true';
const REWRITE_ACCEPT_ENCODING = process.env.REWRITE_ACCEPT_ENCODING === 'true';
const APPEND_HEAD = process.env.APPEND_HEAD === 'true';
const ALLOWED_HOSTS = getHosts(process.env.ALLOWED_HOSTS);
const GZIP_METHOD = process.env.GZIP_METHOD;

assert.ok(ACCESS_KEY, 'Missing ACCESS_KEY');
assert.ok(ALLOWED_GZIP_METHODS.includes(GZIP_METHOD), `GZIP_METHOD must be one of the following values: ${JSON.stringify(ALLOWED_GZIP_METHODS)}`);

const server = http.createServer();

// --- Proxy Server Creation ---
// ADD selfHandleResponse: true
const httpsProxy = proxy.createProxyServer({
  agent: new https.Agent({
    checkServerIdentity: (host, cert) => {
      // Allow self-signed certs for target, basic check
      return undefined;
    }
  }),
  changeOrigin: true,
  selfHandleResponse: true // Let us handle the response stream
});

const httpProxy = proxy.createProxyServer({
  changeOrigin: true,
  selfHandleResponse: true // Let us handle the response stream
});

// --- Helper Functions (Unchanged) ---
const writeErr = (res, status, message) => {
  if (!res.headersSent) {
      res.writeHead(status, {'Content-Type': 'text/plain'});
  }
  res.end(message);
};

const onProxyError = (err, req, res, target) => {
    // Add more context to the error log
    console.error(`Proxy Error for ${req.method} ${target?.href || req.url}:`, err);
    // Check if headers already sent before trying to write error
    if (!res.headersSent) {
        writeErr(res, 502, 'Proxying failed: ' + err.code || err.message); // 502 Bad Gateway often appropriate
    } else {
        // If headers sent, we can't send a new status, just end the connection
        res.end();
    }
};


// --- onProxyReq (Unchanged, but added logging) ---
const onProxyReq = (proxyReq, req, res, options) => {
  // Log the actual request details being sent to the target
  // console.log(`Proxying request to: ${options.target.href}${proxyReq.path}`);
  // console.log('  Method:', proxyReq.method);
  // console.log('  Headers:', proxyReq.getHeaders());

  proxyReq.setHeader('User-Agent', proxyReq.getHeader('proxy-override-user-agent') || DEFAULT_USERAGENT);
  if (REWRITE_ACCEPT_ENCODING) {
    // Ensure we only ask for gzip if we intend to handle it
    proxyReq.setHeader('Accept-Encoding', 'gzip');
  } else {
      // If not rewriting, remove it to avoid getting unexpected encoding
      proxyReq.removeHeader('accept-encoding');
  }
  proxyReq.removeHeader('roblox-id'); // Example internal header to remove
  proxyReq.removeHeader('proxy-access-key');
  proxyReq.removeHeader('proxy-target');
  proxyReq.removeHeader('proxy-target-override-method');
  proxyReq.removeHeader('proxy-target-override-proto');
  proxyReq.removeHeader('proxy-override-user-agent');
  // Add other sensitive headers Robox might send if needed
  proxyReq.removeHeader('cookie'); // Example: often good to remove cookies
};

// --- REVISED onProxyRes using selfHandleResponse ---
const onProxyRes = (proxyRes, req, res) => {
  const head = {
    headers: { ...proxyRes.headers }, // Shallow copy
    status: {
      code: proxyRes.statusCode,
      message: proxyRes.statusMessage
    }
  };

  const append = `"""${JSON.stringify(head)}"""`;
  const encoding = proxyRes.headers['content-encoding'];

  // --- Set Headers for the *outgoing* response to Roblox ---
  // Copy original headers, but remove ones we'll handle/modify
  Object.keys(proxyRes.headers).forEach(key => {
      // Don't copy encoding/length if we modify the body
      if (APPEND_HEAD && (key === 'content-encoding' || key === 'content-length' || key === 'transfer-encoding')) {
          return;
      }
      res.setHeader(key, proxyRes.headers[key]);
  });

  // Set the status code (override if needed)
  res.writeHead(USE_OVERRIDE_STATUS ? 200 : proxyRes.statusCode);

  // --- Handle body streaming and appending ---
  if (!APPEND_HEAD) {
    // If not appending, just pipe the original response directly
    proxyRes.pipe(res);
  } else {
    // We need to append the metadata
    if (encoding === 'gzip') {
      let decoder;
      try {
          decoder = zlib.createGunzip();
      } catch (e) {
          console.error("Failed to create Gunzip stream:", e);
          writeErr(res, 500, "Internal server error during decompression");
          proxyRes.resume(); // Consume the rest of the stream to prevent hangs
          return;
      }

      if (GZIP_METHOD === 'transform') {
        let encoder;
        try {
            encoder = zlib.createGzip();
        } catch (e) {
            console.error("Failed to create Gzip stream:", e);
            writeErr(res, 500, "Internal server error during recompression");
            proxyRes.resume();
            return;
        }
        // Set correct encoding header for the *final* response
        res.setHeader('content-encoding', 'gzip');

        // Pipeline: Target Response -> Gunzip -> Gzip -> Roblox Response
        proxyRes.pipe(decoder);
        decoder.pipe(encoder); // Pipe decoded data to encoder
        encoder.pipe(res, { end: false }); // Pipe re-encoded data to Roblox, keep stream open

        // When the original response is fully decoded and piped to encoder...
        decoder.on('end', () => {
          // console.log("Decoder ended, writing append to encoder");
          // Write the plain metadata to the encoder, then end the encoder
          encoder.end(append);
        });
        // When the encoder finishes (after processing original + append)...
        encoder.on('end', () => {
          // console.log("Encoder ended, ending response to Roblox");
          // End the response to Roblox
          res.end();
        });

        // Error handling for streams
        proxyRes.on('error', (err) => { console.error('proxyRes stream error:', err); res.end(); });
        decoder.on('error', (err) => { console.error('decoder stream error:', err); res.end(); });
        encoder.on('error', (err) => { console.error('encoder stream error:', err); res.end(); });

      } else if (GZIP_METHOD === 'decode') {
        // Pipeline: Target Response -> Gunzip -> Roblox Response (decoded)
        res.removeHeader('content-encoding'); // We are sending decoded data

        proxyRes.pipe(decoder);
        decoder.pipe(res, { end: false }); // Pipe decoded data to Roblox, keep stream open

        decoder.on('end', () => {
          // console.log("Decoder ended, writing append and ending response");
          // Write plain metadata and end the response
          res.end(append);
        });

        // Error handling
        proxyRes.on('error', (err) => { console.error('proxyRes stream error:', err); res.end(); });
        decoder.on('error', (err) => { console.error('decoder stream error:', err); res.end(); });

      } else { // GZIP_METHOD === 'append' or unknown (Treat as append, likely won't work correctly)
         console.warn(`GZIP_METHOD 'append' is not recommended for gzipped content.`);
         // Attempt to just pipe original gzipped data and append plain text - will likely corrupt client-side
         res.setHeader('content-encoding', 'gzip'); // Keep original encoding header
         proxyRes.pipe(res, { end: false }); // Pipe gzipped data, keep stream open
         proxyRes.on('end', () => {
            // console.log("ProxyRes ended (append mode), writing append and ending response");
            res.end(append); // Append plain text - client will likely fail to decode
         });
         proxyRes.on('error', (err) => { console.error('proxyRes stream error (append mode):', err); res.end(); });
      }
    } else { // Not gzipped
      // Pipeline: Target Response -> Roblox Response
      proxyRes.pipe(res, { end: false }); // Pipe plain data, keep stream open
      proxyRes.on('end', () => {
        // console.log("ProxyRes ended (no gzip), writing append and ending response");
        res.end(append); // Append plain metadata and end
      });
      proxyRes.on('error', (err) => { console.error('proxyRes stream error (no gzip):', err); res.end(); });
    }
  }
};

// --- Assign error/request/response handlers (Unchanged) ---
httpsProxy.on('error', onProxyError);
httpsProxy.on('proxyReq', onProxyReq);
httpsProxy.on('proxyRes', onProxyRes);

httpProxy.on('error', onProxyError);
httpProxy.on('proxyReq', onProxyReq);
httpProxy.on('proxyRes', onProxyRes);


// --- doProxy (Pass options correctly) ---
const doProxy = (targetUrl, proto, req, res) => { // targetUrl is now a URL object
  const options = {
    target: `${proto}://${targetUrl.hostname}${targetUrl.port ? ':' + targetUrl.port : ''}`, // Base target URL
    // path is handled automatically by http-proxy based on req.url
    // headers are handled by onProxyReq
  };
  // console.log(`Executing proxy with options:`, options);
  if (proto === 'https') {
    httpsProxy.web(req, res, options);
  } else if (proto === 'http') {
    httpProxy.web(req, res, options);
  } else {
    // This case should ideally not be reached due to prior checks
    console.error(`Do proxy error: Unsupported protocol ${proto}`);
    writeErr(res, 500, `Internal Server Error: Unsupported protocol ${proto}`);
  }
};

// --- server.on('request') (Minor improvements) ---
server.on('request', (req, res) => {
  // Add basic logging for incoming requests
  // console.log(`Incoming request: ${req.method} ${req.url}`);
  // console.log('  Headers:', req.headers);

  // --- Header Parsing and Validation ---
  const methodOverride = req.headers['proxy-target-override-method'];
  const originalMethod = req.method; // Store original method
  if (methodOverride) {
    if (ALLOWED_METHODS.includes(methodOverride)) {
      req.method = methodOverride; // Override method for proxy request
    } else {
      writeErr(res, 400, 'Invalid target method override');
      return;
    }
  }

  const protoOverride = req.headers['proxy-target-override-proto'];
  if (protoOverride && !ALLOWED_PROTOS.includes(protoOverride)) {
    writeErr(res, 400, 'Invalid target protocol override');
    return;
  }

  const accessKeyHeader = req.headers['proxy-access-key'];
  const targetHeader = req.headers['proxy-target'];

  if (!accessKeyHeader || !targetHeader) {
      writeErr(res, 400, 'proxy-access-key and proxy-target headers are both required');
      return;
  }

  // --- Access Key Check ---
  const accessKeyBuffer = Buffer.from(accessKeyHeader); // Use the actual header value
  // Ensure ACCESS_KEY is defined before comparing
  if (!ACCESS_KEY || accessKeyBuffer.length !== ACCESS_KEY.length || !crypto.timingSafeEqual(accessKeyBuffer, ACCESS_KEY)) {
      writeErr(res, 403, 'Invalid access key');
      return;
  }

  // --- Target URL Parsing and Whitelist Check ---
  let parsedTargetUrl; // Use URL object for better parsing
  try {
      // Construct a full potential URL to parse host/path correctly
      // Use https as default for parsing if target doesn't specify
      let tempUrl = targetHeader;
      if (!tempUrl.includes('://')) {
          tempUrl = `${DEFAULT_PROTO}://${tempUrl}`;
      }
      // Add the original request path to the target host
      parsedTargetUrl = new URL(req.url, tempUrl);

      // Basic check if hostname seems valid (can be improved)
       if (!parsedTargetUrl.hostname || !parsedTargetUrl.hostname.includes('.')) {
           throw new Error("Hostname seems invalid");
       }

  } catch (e) {
      console.error(`Invalid target URL format: ${targetHeader}${req.url}`, e);
      writeErr(res, 400, 'Invalid target URL format');
      return;
  }

  const requestedHost = parsedTargetUrl.hostname; // Use hostname from URL object
  let hostAllowed = !USE_WHITELIST; // Allowed by default if whitelist is off
  let hostProto = protoOverride || DEFAULT_PROTO; // Use override or default

  if (USE_WHITELIST) {
      for (let i = 0; i < ALLOWED_HOSTS.length; i++) {
          const iHost = ALLOWED_HOSTS[i];
          if (requestedHost === iHost.host) {
              hostAllowed = true;
              // Potentially use a specific proto defined for this host in future
              break;
          }
      }
  }

  // Determine final protocol (use override if specified, otherwise default)
  hostProto = protoOverride || DEFAULT_PROTO;


  if (hostAllowed) {
      // Restore original method before passing to doProxy if it was overridden for validation?
      // No, http-proxy uses req.method, so keep the override if it exists.
      // console.log(`Proxying to ${hostProto}://${requestedHost}${parsedTargetUrl.pathname}${parsedTargetUrl.search}`);
      req.url = `${parsedTargetUrl.pathname}${parsedTargetUrl.search}`; // Update req.url for http-proxy
      doProxy(parsedTargetUrl, hostProto, req, res); // Pass URL object
  } else {
      writeErr(res, 400, `Host not whitelisted: ${requestedHost}`);
  }
});

// --- Server Listen (Unchanged) ---
server.listen(PORT, (err) => {
  if (err) {
    console.error(`Server listening error: ${err}`);
    return;
  }
  console.log(`ProxyService started on port ${PORT}`);
  console.log(`Config: APPEND_HEAD=${APPEND_HEAD}, USE_OVERRIDE_STATUS=${USE_OVERRIDE_STATUS}, GZIP_METHOD=${GZIP_METHOD}, REWRITE_ACCEPT_ENCODING=${REWRITE_ACCEPT_ENCODING}, USE_WHITELIST=${USE_WHITELIST}`);
  if (USE_WHITELIST) {
      console.log(`Allowed Hosts: ${ALLOWED_HOSTS.map(h => h.host).join(', ')}`);
  }
});
