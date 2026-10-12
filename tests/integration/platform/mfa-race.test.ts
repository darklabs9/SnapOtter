import * as OTPAuth from "otpauth";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

vi.resetModules();
const { mockEnterpriseFeatures } = await import("../../helpers/enterprise-mock.js");
mockEnterpriseFeatures(["mfa"]);

const { buildTestApp, createUserAndLogin } = await import("../test-server.js");

import type { TestApp } from "../test-server.js";

function generateTotpCode(uri: string): string {
  const totp = OTPAuth.URI.parse(uri) as OTPAuth.TOTP;
  return totp.generate();
}

describe("MFA Race Condition #2328", () => {
  let testApp: TestApp;

  beforeAll(async () => {
    testApp = await buildTestApp();
  });

  afterAll(async () => {
    if (testApp) {
      await testApp.app.close();
    }
  });

  it("should not allow completing MFA twice concurrently with the same code", async () => {
    const username = `mfaraceuser_${Date.now()}`;
    const password = "Userpass1";
    // Create a user and log in to get a session
    const { token: userToken } = await createUserAndLogin(testApp.app, username, "user", password);

    // Enroll MFA
    const enrollRes = await testApp.app.inject({
      method: "POST",
      url: "/api/auth/mfa/enroll",
      headers: { authorization: `Bearer ${userToken}` },
    });
    expect(enrollRes.statusCode).toBe(200);
    const { uri } = JSON.parse(enrollRes.body);

    // Verify MFA to enable it
    const verifyRes = await testApp.app.inject({
      method: "POST",
      url: "/api/auth/mfa/verify",
      headers: { authorization: `Bearer ${userToken}` },
      payload: { code: generateTotpCode(uri) },
    });
    expect(verifyRes.statusCode).toBe(200);

    // Now log in to trigger an MFA challenge
    const loginRes = await testApp.app.inject({
      method: "POST",
      url: "/api/auth/login",
      payload: { username, password },
    });
    expect(loginRes.statusCode).toBe(200);
    const { mfaToken, requiresMfa } = JSON.parse(loginRes.body);
    expect(requiresMfa).toBe(true);
    expect(mfaToken).toBeDefined();

    // Generate a new code for the challenge
    const code = generateTotpCode(uri);

    // Race two complete requests
    const [res1, res2] = await Promise.all([
      testApp.app.inject({
        method: "POST",
        url: "/api/auth/mfa/complete",
        payload: { mfaToken, code },
      }),
      testApp.app.inject({
        method: "POST",
        url: "/api/auth/mfa/complete",
        payload: { mfaToken, code },
      }),
    ]);

    const statuses = [res1.statusCode, res2.statusCode].sort();

    // We expect exactly one 200 OK and one 401 Unauthorized
    expect(statuses[0]).toBe(200);
    expect(statuses[1]).toBe(401);
  });
});
