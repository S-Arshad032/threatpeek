// Production entry point used by the root "npm start". Setting NODE_ENV here (instead of
// "NODE_ENV=production node ...") works the same in every shell, including Windows cmd.
process.env.NODE_ENV = "production";
await import("./index.js");
