// Runs web/verify.js under node for tests/web/test_verify_page.py.
// argv[2]: path of the verify.js to load. stdin: JSON list of operations. stdout: JSON list of results.
"use strict";

const path = require("path");
const verify = require(path.resolve(process.argv[2]));

function notSupported() {
  return new DOMException("Unrecognized name.", "NotSupportedError");
}

// A WebCrypto that has SHA-256 but no Ed25519, the way an older browser behaves.
function stubbedSubtle(where) {
  const real = globalThis.crypto.subtle;
  return {
    digest: (alg, data) => real.digest(alg, data),
    importKey: async (...args) => {
      if (where === "importKey") throw notSupported();
      return real.importKey(...args);
    },
    verify: async (...args) => {
      if (where === "verify") throw notSupported();
      return real.verify(...args);
    },
  };
}

async function run(op) {
  try {
    switch (op.op) {
      case "canonical":
        return { hex: Buffer.from(verify.canonicalBytes(op.text)).toString("hex") };
      case "verify":
        return await verify.verifyReceiptText(op.text, op.key);
      case "verify_stubbed": {
        if (op.stub === "no-crypto-global") {
          const saved = Object.getOwnPropertyDescriptor(globalThis, "crypto");
          Object.defineProperty(globalThis, "crypto", { value: undefined, configurable: true, writable: true });
          try {
            return await verify.verifyReceiptText(op.text, op.key);
          } finally {
            Object.defineProperty(globalThis, "crypto", saved);
          }
        }
        const subtle = op.stub === "no-subtle" ? undefined : stubbedSubtle(op.stub);
        return await verify.verifyReceiptText(op.text, op.key, { subtle });
      }
      case "tamper":
        return verify.changeOneByte(op.text);
      case "forge":
        return verify.forgeSignature(op.text);
      case "published_key":
        return { key: verify.PUBLISHED_KEY };
      default:
        return { error: "unknown op " + op.op };
    }
  } catch (e) {
    return { error: String((e && e.message) || e), error_name: e && e.name };
  }
}

let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => { input += chunk; });
process.stdin.on("end", async () => {
  const out = [];
  for (const op of JSON.parse(input)) out.push(await run(op));
  process.stdout.write(JSON.stringify(out));
});
