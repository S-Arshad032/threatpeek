import { describe, expect, it } from "vitest";
import { loadEnv } from "../src/env.js";

describe("loadEnv", () => {
  it("uses safe defaults when nothing is set", () => {
    const env = loadEnv({});
    expect(env.PORT).toBe(3001);
    expect(env.ALLOWED_ORIGINS).toEqual(["http://localhost:5173"]);
    expect(env.GOOGLE_SAFE_BROWSING_KEY).toBeUndefined();
    expect(env.AI_ENABLED).toBe(false);
    expect(env.OPENROUTER_API_KEY).toBeUndefined();
    expect(env.AI_DAILY_LIMIT).toBe(40);
    expect(env.NODE_ENV).toBe("development");
    expect(env.aiActive).toBe(false);
  });

  it("treats empty strings as unset", () => {
    const env = loadEnv({ GOOGLE_SAFE_BROWSING_KEY: "  ", OPENROUTER_API_KEY: "", PORT: "", AI_DAILY_LIMIT: "" });
    expect(env.GOOGLE_SAFE_BROWSING_KEY).toBeUndefined();
    expect(env.OPENROUTER_API_KEY).toBeUndefined();
    expect(env.PORT).toBe(3001);
    expect(env.AI_DAILY_LIMIT).toBe(40);
  });

  it("parses a comma separated origin list", () => {
    const env = loadEnv({ ALLOWED_ORIGINS: "https://a.example, https://b.example ,," });
    expect(env.ALLOWED_ORIGINS).toEqual(["https://a.example", "https://b.example"]);
  });

  it("only enables AI with AI_ENABLED=true, a key and a model", () => {
    expect(loadEnv({ AI_ENABLED: "true", OPENROUTER_API_KEY: "k", OPENROUTER_MODEL: "m" }).aiActive).toBe(true);
    expect(loadEnv({ AI_ENABLED: "TRUE", OPENROUTER_API_KEY: "k", OPENROUTER_MODEL: "m" }).aiActive).toBe(false);
    expect(loadEnv({ AI_ENABLED: "1", OPENROUTER_API_KEY: "k", OPENROUTER_MODEL: "m" }).aiActive).toBe(false);
    expect(loadEnv({ AI_ENABLED: "true", OPENROUTER_MODEL: "m" }).aiActive).toBe(false);
    expect(loadEnv({ AI_ENABLED: "true", OPENROUTER_API_KEY: "k" }).aiActive).toBe(false);
  });

  it("falls back to defaults for invalid numbers", () => {
    const env = loadEnv({ PORT: "abc", AI_DAILY_LIMIT: "-5" });
    expect(env.PORT).toBe(3001);
    expect(env.AI_DAILY_LIMIT).toBe(40);
    expect(loadEnv({ PORT: "8080", AI_DAILY_LIMIT: "10" })).toMatchObject({ PORT: 8080, AI_DAILY_LIMIT: 10 });
  });

  it("returns a frozen object", () => {
    expect(Object.isFrozen(loadEnv({}))).toBe(true);
  });
});
