import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";

import worker from "../src/index";

const token = "expected-token";
const configuredEnv = {
  DUSK_GATEWAY_TOKEN: token,
  DUSK_ORIGIN: "https://dusk.example.com/base/",
};

async function dispatch(
  request: Request,
  env: Env = configuredEnv as Env,
  fetcher: typeof fetch = fetch,
): Promise<Response> {
  vi.stubGlobal("fetch", fetcher);
  const context = createExecutionContext();
  // The test runtime's Request type is narrower than the generated Worker handler type.
  const response = await worker.fetch(request as never, env, context);
  await waitOnExecutionContext(context);
  return response;
}

function validRequest(body = '{"action_type":"read"}'): Request {
  return new Request("https://worker.example/v1/actions/evaluate", {
    body,
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    method: "POST",
  });
}

describe("DUSK Cloudflare gateway", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("rejects unknown paths without contacting DUSK", async () => {
    const fetcher = vi.fn<typeof fetch>();

    const response = await dispatch(
      new Request("https://worker.example/unexpected", { method: "POST" }),
      configuredEnv as Env,
      fetcher,
    );

    expect(response.status).toBe(404);
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("rejects a non-POST action request without contacting DUSK", async () => {
    const fetcher = vi.fn<typeof fetch>();

    const response = await dispatch(
      new Request("https://worker.example/v1/actions/evaluate", {
        headers: { Authorization: `Bearer ${token}` },
      }),
      configuredEnv as Env,
      fetcher,
    );

    expect(response.status).toBe(405);
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("rejects a missing bearer token without contacting DUSK", async () => {
    const fetcher = vi.fn<typeof fetch>();
    const request = new Request("https://worker.example/v1/actions/evaluate", {
      body: "{}",
      headers: { "Content-Type": "application/json" },
      method: "POST",
    });

    const response = await dispatch(request, configuredEnv as Env, fetcher);

    expect(response.status).toBe(401);
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("rejects a request without JSON content type without contacting DUSK", async () => {
    const fetcher = vi.fn<typeof fetch>();
    const request = new Request("https://worker.example/v1/actions/evaluate", {
      body: "{}",
      headers: { Authorization: `Bearer ${token}` },
      method: "POST",
    });

    const response = await dispatch(request, configuredEnv as Env, fetcher);

    expect(response.status).toBe(400);
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("rejects invalid JSON without contacting DUSK", async () => {
    const fetcher = vi.fn<typeof fetch>();

    const response = await dispatch(validRequest("{"), configuredEnv as Env, fetcher);

    expect(response.status).toBe(400);
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("rejects an oversized action request without contacting DUSK", async () => {
    const fetcher = vi.fn<typeof fetch>();

    const response = await dispatch(validRequest(`{"value":"${"x".repeat(65_537)}"}`), configuredEnv as Env, fetcher);

    expect(response.status).toBe(413);
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("fails closed when DUSK configuration is absent", async () => {
    const fetcher = vi.fn<typeof fetch>();

    const response = await dispatch(validRequest(), {} as Env, fetcher);

    expect(response.status).toBe(503);
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("fails closed when the configured DUSK origin is not HTTPS", async () => {
    const fetcher = vi.fn<typeof fetch>();
    const env = { ...configuredEnv, DUSK_ORIGIN: "http://dusk.example.com" } as Env;

    const response = await dispatch(validRequest(), env, fetcher);

    expect(response.status).toBe(503);
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("forwards a valid action only to the configured DUSK endpoint", async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(
      Response.json({ decision: "BLOCK" }, { status: 403 }),
    );

    const response = await dispatch(validRequest(), configuredEnv as Env, fetcher);

    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ decision: "BLOCK" });
    expect(response.headers.get("X-DUSK-Request-ID")).toMatch(/^[0-9a-f-]{36}$/);
    expect(fetcher).toHaveBeenCalledTimes(1);
    const [url, init] = fetcher.mock.calls[0] ?? [];
    expect(String(url)).toBe("https://dusk.example.com/v1/actions/evaluate");
    expect(init?.method).toBe("POST");
    expect(new Headers(init?.headers).get("X-DUSK-Gateway")).toBe("cloudflare-worker");
    expect(new Headers(init?.headers).get("X-DUSK-Gateway-Token")).toBe(token);
    expect(new Headers(init?.headers).get("X-DUSK-Request-ID")).toBe(response.headers.get("X-DUSK-Request-ID"));
  });

  it("returns 502 when DUSK cannot be reached", async () => {
    const fetcher = vi.fn<typeof fetch>().mockRejectedValue(new Error("connection refused"));

    const response = await dispatch(validRequest(), configuredEnv as Env, fetcher);

    expect(response.status).toBe(502);
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
});
