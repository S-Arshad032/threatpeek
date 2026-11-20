// Shared helpers for JSON responses and body validation.

/** Sends `{ error, message }` with plain-English text. Never includes stack traces. */
export function sendError(res, status, error, message) {
  return res.status(status).json({ error, message });
}

/**
 * Validates req.body with a zod schema. On failure sends 400 and returns undefined.
 * The zod issues are not echoed back (they may quote untrusted input).
 */
export function parseBody(schema, req, res) {
  const result = schema.safeParse(req.body);
  if (!result.success) {
    sendError(res, 400, "invalid_request", "The request body is missing a field or has a wrong value.");
    return undefined;
  }
  return result.data;
}
