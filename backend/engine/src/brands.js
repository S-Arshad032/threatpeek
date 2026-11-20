// Default brand data for typosquatting and display-name-mismatch detection.
// Fictional brands and reserved TLDs only. Callers can replace this list through
// `options.brands`; the engine logic does not depend on these particular entries.
// Brand names are lowercase, a-z0-9 only.

/** @typedef {{ name: string, domains: string[] }} BrandEntry */

/** @type {ReadonlyArray<BrandEntry>} */
export const DEFAULT_BRANDS = Object.freeze([
  Object.freeze({ name: "galactibank", domains: Object.freeze(["galactibank.example"]) }),
  Object.freeze({ name: "orbitins", domains: Object.freeze(["orbitins.test"]) }),
  Object.freeze({ name: "nexamail", domains: Object.freeze(["nexamail.example"]) }),
  Object.freeze({ name: "vaultpay", domains: Object.freeze(["vaultpay.example"]) }),
  Object.freeze({ name: "trustledger", domains: Object.freeze(["trustledger.test"]) }),
]);
