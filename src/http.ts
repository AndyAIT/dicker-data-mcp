import { createServer as createHttpServer, type Server as HttpServer } from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createServer } from './server.js';
import { runWithCredentials } from './client.js';
import { logger } from './utils/logger.js';
import type { DickerDataCredentials } from './types.js';

/*
 * Adept Copilot Studio authentication
 *
 * The original WYRE Conduit X-Gateway-S2S authentication has been replaced
 * with a static X-API-Key authentication mechanism suitable for Microsoft
 * Copilot Studio.
 *
 * The expected key is read from:
 *
 *   COPILOT_MCP_API_KEY
 *
 * Every request to /mcp must provide:
 *
 *   X-API-Key: <configured key>
 *
 * The /health endpoint remains unauthenticated for container health checks.
 * Dicker Data credentials remain server-side and are read through AUTH_MODE=env.
 */

const KNOWN_PLACEHOLDER_KEYS = new Set([
  'replace-with-a-real-secret',
  'your-api-key',
  'your-secret',
  'changeme',
  'change-me',
  'placeholder',
  'secret',
  'example',
  'replace-me',
  'api-key',
]);

const MISSING_API_KEY_ERROR =
  'Refusing to start HTTP transport: COPILOT_MCP_API_KEY is empty. ' +
  'Generate a strong random key and configure COPILOT_MCP_API_KEY.';

const PLACEHOLDER_API_KEY_ERROR =
  'Refusing to start HTTP transport: COPILOT_MCP_API_KEY is a known placeholder. ' +
  'Generate and configure a strong random key.';

const API_KEY_UNAUTHORIZED = {
  error: 'Unauthorized: missing or invalid X-API-Key header.',
};

const GATEWAY_CREDENTIALS_UNAUTHORIZED = {
  error:
    'Unauthorized: missing required gateway credential headers ' +
    'x-dickerdata-account-code and x-dickerdata-access-token',
};

function headerValue(
  value: string | string[] | undefined,
): string | undefined {
  const raw = Array.isArray(value) ? value[0] : value;

  if (typeof raw !== 'string') {
    return undefined;
  }

  const trimmed = raw.trim();

  return trimmed.length > 0 ? trimmed : undefined;
}

/**
 * Read the Copilot MCP API key at HTTP startup.
 *
 * HTTP startup fails closed if the key is empty or is a known placeholder.
 * The key itself is never logged.
 */
function resolveCopilotApiKey(): string {
  const apiKey = (process.env.COPILOT_MCP_API_KEY ?? '').trim();

  if (!apiKey) {
    logger.error(MISSING_API_KEY_ERROR);
    process.exit(1);
  }

  if (KNOWN_PLACEHOLDER_KEYS.has(apiKey.toLowerCase())) {
    logger.error(PLACEHOLDER_API_KEY_ERROR);
    process.exit(1);
  }

  if (apiKey.length < 32) {
    logger.error(
      'Refusing to start HTTP transport: COPILOT_MCP_API_KEY must be at least 32 characters long.',
    );
    process.exit(1);
  }

  return apiKey;
}

/**
 * Compare the provided API key with the configured key using a timing-safe
 * comparison. Different-length values are rejected before comparison because
 * timingSafeEqual requires equal-sized buffers.
 */
function verifyApiKey(
  providedApiKey: string | undefined,
  expectedApiKey: string,
): boolean {
  if (!providedApiKey) {
    return false;
  }

  const providedBuffer = Buffer.from(providedApiKey, 'utf8');
  const expectedBuffer = Buffer.from(expectedApiKey, 'utf8');

  if (providedBuffer.length !== expectedBuffer.length) {
    return false;
  }

  return timingSafeEqual(providedBuffer, expectedBuffer);
}

export async function startHttpServer(): Promise<HttpServer> {
  const copilotApiKey = resolveCopilotApiKey();
  const port = parseInt(process.env.MCP_HTTP_PORT || '8080', 10);
  const host = (process.env.MCP_HTTP_HOST ?? '').trim() || '0.0.0.0';
  const isGatewayMode = process.env.AUTH_MODE === 'gateway';

  const httpServer = createHttpServer(async (req, res) => {
    logger.info(`HTTP request: ${req.method} ${req.url}`);
	const url = new URL(
      req.url || '/',
      `http://${req.headers.host || 'localhost'}`,
    );

    /*
     * Container liveness endpoint.
     *
     * This intentionally does not expose credential readiness and does not
     * require the API key, allowing Docker and reverse proxies to perform
     * health checks.
     */
    if (url.pathname === '/health') {
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
      });

      res.end(
        JSON.stringify({
          status: 'ok',
          transport: 'http',
          mode: isGatewayMode ? 'gateway' : 'standalone',
          authentication: 'api-key',
          timestamp: new Date().toISOString(),
        }),
      );

      return;
    }

    if (url.pathname !== '/mcp') {
      res.writeHead(404, {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
      });

      res.end(
        JSON.stringify({
          error: 'Not found',
          endpoints: ['/mcp', '/health'],
        }),
      );

      return;
    }

    /*
     * Copilot Studio authentication.
     *
     * Every request to /mcp must supply:
     *
     *   X-API-Key: <COPILOT_MCP_API_KEY>
     */
    const providedApiKey = headerValue(req.headers['x-api-key']);

    if (!verifyApiKey(providedApiKey, copilotApiKey)) {
      res.writeHead(401, {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
      });

      res.end(JSON.stringify(API_KEY_UNAUTHORIZED));
      return;
    }

    const accountCode = headerValue(
      req.headers['x-dickerdata-account-code'],
    );

    const accessToken = headerValue(
      req.headers['x-dickerdata-access-token'],
    );

    const handle = async () => {
      /*
       * Keep this transport stateless.
       *
       * This preserves the original upstream MCP transport behaviour.
       */
      const server = createServer();

      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });

      res.on('close', () => {
        transport.close();
        server.close();
      });

      await server.connect(transport);
      await transport.handleRequest(req, res);
    };

    /*
     * Gateway mode retains the original per-request Dicker credential
     * behaviour if it is ever deliberately enabled.
     */
    if (isGatewayMode) {
      if (!accountCode || !accessToken) {
        res.writeHead(401, {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store',
        });

        res.end(JSON.stringify(GATEWAY_CREDENTIALS_UNAUTHORIZED));
        return;
      }

      const credentials: DickerDataCredentials = {
        accountCode,
        accessToken,
      };

      await runWithCredentials(credentials, handle);
      return;
    }

    /*
     * Env/single-tenant mode.
     *
     * If both per-request Dicker headers are present, use them. Otherwise,
     * the Dicker tools resolve DICKERDATA_ACCOUNT_CODE and
     * DICKERDATA_ACCESS_TOKEN from the process environment.
     */
    if (accountCode && accessToken) {
      await runWithCredentials(
        {
          accountCode,
          accessToken,
        },
        handle,
      );

      return;
    }

    await handle();
  });

  await new Promise<void>((resolve, reject) => {
    httpServer.once('error', reject);

    httpServer.listen(port, host, () => {
      logger.info(
        `HTTP streaming server listening on ${host}:${port} with X-API-Key authentication`,
      );

      resolve();
    });
  });

  return httpServer;
}

/*
 * Entry point.
 *
 * Vitest imports this module to call startHttpServer. Running
 * node dist/http.js starts HTTP when MCP_TRANSPORT=http, otherwise it
 * falls through to the stdio entry point.
 */
if (process.env.VITEST !== 'true') {
  if (process.env.MCP_TRANSPORT === 'http') {
    startHttpServer().catch((error) => {
      logger.error('Fatal startup error', {
        error: error instanceof Error ? error.message : String(error),
      });

      process.exit(1);
    });
  } else {
    await import('./index.js');
  }
}