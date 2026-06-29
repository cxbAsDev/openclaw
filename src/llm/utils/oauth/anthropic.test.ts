// Anthropic OAuth tests cover token exchange and refresh behavior.
import { afterEach, describe, expect, it, vi } from "vitest";
import { anthropicOAuthProvider, refreshAnthropicToken } from "./anthropic.js";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Anthropic OAuth token responses", () => {
  it("cancels provider login before opening the OAuth flow", async () => {
    const controller = new AbortController();
    controller.abort();

    await expect(
      anthropicOAuthProvider.login({
        onAuth: vi.fn(),
        onPrompt: vi.fn(async () => "unused-code"),
        signal: controller.signal,
      }),
    ).rejects.toThrow("Login cancelled");
  });

  it("does not open the OAuth flow after cancellation during setup", async () => {
    const controller = new AbortController();
    const onAuth = vi.fn();
    const loginPromise = anthropicOAuthProvider.login({
      onAuth,
      onPrompt: vi.fn(async () => "unused-code"),
      signal: controller.signal,
    });

    controller.abort();

    await expect(loginPromise).rejects.toThrow("Login cancelled");
    expect(onAuth).not.toHaveBeenCalled();
  });

  it("does not echo token payload values when refresh JSON parsing fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response('{"access_token":"secret-access-token","refresh_token":"secret-refresh"', {
            status: 200,
          }),
      ),
    );

    await expect(refreshAnthropicToken("old-refresh-token")).rejects.toThrow(
      "Anthropic token refresh returned invalid JSON.",
    );

    try {
      await refreshAnthropicToken("old-refresh-token");
      throw new Error("Expected refresh to fail");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      expect(message).not.toContain("secret-access-token");
      expect(message).not.toContain("secret-refresh");
      expect(message).not.toContain("access_token");
      expect(message).not.toContain("refresh_token");
      expect(message).toContain("bodyBytes=");
    }
  });

  it("rejects unsafe token lifetimes from refresh responses", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            '{"access_token":"new-access-token","refresh_token":"new-refresh-token","expires_in":1e309}',
            { status: 200 },
          ),
      ),
    );

    await expect(refreshAnthropicToken("old-refresh-token")).rejects.toThrow(
      "Anthropic token refresh returned invalid token fields.",
    );
  });

  it("rejects oversized token refresh responses", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => makeOversizedOAuthJsonResponse()));

    await expect(refreshAnthropicToken("old-refresh-token")).rejects.toThrow(
      "Anthropic OAuth token response exceeds",
    );
  });
});

/**
 * Builds a JSON response body larger than the 16 MiB OAuth cap so the bounded
 * reader cancels the stream mid-flight; proves oversized token responses are
 * rejected before full buffering.
 */
function makeOversizedOAuthJsonResponse(): Response {
  const ONE_MIB = 1024 * 1024;
  const TOTAL_CHUNKS = 18;
  const chunk = new Uint8Array(ONE_MIB);
  let pulled = 0;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (pulled >= TOTAL_CHUNKS) {
        controller.close();
        return;
      }
      pulled += 1;
      controller.enqueue(chunk);
    },
  });
  return new Response(body, {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}
