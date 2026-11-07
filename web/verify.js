/* Check a Rehearsal Twin receipt in the browser (or in node, for the tests).

   The signed bytes are what rt/receipts/sign.py signs: Python's
   json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
   in UTF-8, where body is the receipt without its top-level "signature". JSON.parse followed by
   JSON.stringify would turn 60.0 into 60 and change those bytes, so this file has its own small
   JSON parser that keeps every number as the exact text it arrived in.

   PASS needs all three: the Ed25519 signature matches the canonical bytes for the key inside the
   receipt, signature.key_id is the first 16 hex of sha256 of that key, and that key is the
   published one. Without Ed25519 in WebCrypto the answer is "unsupported", never PASS. */
(function () {
  "use strict";

  const PUBLISHED_KEY = "rYyVzKw04aG8Y278Q1QsS1xeqBLAwX4NOHt4FWpryy4=";
  const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  /* ------------------------------------------------------------------ JSON that keeps number text */

  class JsonNumber {
    constructor(lexeme) { this.lexeme = lexeme; }
    toString() { return this.lexeme; }
  }

  class ReceiptSyntaxError extends Error {}

  const NUMBER_RE = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
  const STRING_RE = /"(?:[^"\\\u0000-\u001f]|\\["\\/bfnrt]|\\u[0-9a-fA-F]{4})*"/y;
  const MAX_DEPTH = 512;

  function hasLoneSurrogate(s) {
    for (let k = 0; k < s.length; k++) {
      const c = s.charCodeAt(k);
      if (c >= 0xd800 && c <= 0xdbff) {
        const d = s.charCodeAt(k + 1);
        if (!(d >= 0xdc00 && d <= 0xdfff)) return true;
        k++;
      } else if (c >= 0xdc00 && c <= 0xdfff) {
        return true;
      }
    }
    return false;
  }

  function isObject(v) {
    return v !== null && typeof v === "object" && !Array.isArray(v) && !(v instanceof JsonNumber);
  }

  /* Parse JSON text. Objects come back with a null prototype (so a "__proto__" key is just a key),
     numbers as JsonNumber. When `spans` is an array, every string and number value is recorded
     there as {kind, path, start, end} with offsets into `text`. */
  function parse(text, spans) {
    if (typeof text !== "string") throw new ReceiptSyntaxError("the receipt is not text");
    const n = text.length;
    let i = 0;

    function fail(msg) { throw new ReceiptSyntaxError(msg + " at character " + (i + 1)); }

    function ws() {
      while (i < n) {
        const c = text.charCodeAt(i);
        if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
        else break;
      }
    }

    function string() {
      STRING_RE.lastIndex = i;
      const m = STRING_RE.exec(text);
      if (!m) fail("bad string (a raw control character or a bad escape)");
      const s = JSON.parse(m[0]);
      if (hasLoneSurrogate(s)) fail("string with a lone surrogate");
      i = STRING_RE.lastIndex;
      return s;
    }

    function record(kind, path, start) {
      if (spans) spans.push({ kind: kind, path: path, start: start, end: i });
    }

    function value(path, depth) {
      if (depth > MAX_DEPTH) fail("nesting too deep");
      ws();
      if (i >= n) fail("unexpected end of text");
      const start = i;
      const c = text[i];
      if (c === "{") {
        i++;
        const obj = Object.create(null);
        ws();
        if (text[i] === "}") { i++; return obj; }
        for (;;) {
          ws();
          if (text[i] !== '"') fail("expected a key in double quotes");
          const keyAt = i;
          const key = string();
          if (Object.prototype.hasOwnProperty.call(obj, key)) {
            i = keyAt;
            fail("the key " + JSON.stringify(key) + " appears twice");
          }
          ws();
          if (text[i] !== ":") fail("expected ':'");
          i++;
          obj[key] = value(path.concat([key]), depth + 1);
          ws();
          if (text[i] === ",") { i++; continue; }
          if (text[i] === "}") { i++; return obj; }
          fail("expected ',' or '}'");
        }
      }
      if (c === "[") {
        i++;
        const arr = [];
        ws();
        if (text[i] === "]") { i++; return arr; }
        for (;;) {
          arr.push(value(path.concat([arr.length]), depth + 1));
          ws();
          if (text[i] === ",") { i++; continue; }
          if (text[i] === "]") { i++; return arr; }
          fail("expected ',' or ']'");
        }
      }
      if (c === '"') {
        const s = string();
        record("string", path, start);
        return s;
      }
      if (text.startsWith("true", i)) { i += 4; return true; }
      if (text.startsWith("false", i)) { i += 5; return false; }
      if (text.startsWith("null", i)) { i += 4; return null; }
      NUMBER_RE.lastIndex = i;
      const m = NUMBER_RE.exec(text);
      if (!m) fail("unexpected " + JSON.stringify(c));
      if (!Number.isFinite(Number(m[0]))) fail("number out of range");
      i = NUMBER_RE.lastIndex;
      record("number", path, start);
      return new JsonNumber(m[0]);
    }

    const v = value([], 0);
    ws();
    if (i !== n) fail("extra text after the JSON value");
    return v;
  }

  /* --------------------------------------------------------------- canonical form, as Python writes it */

  function compareCodePoints(a, b) {
    let i = 0;
    let j = 0;
    while (i < a.length && j < b.length) {
      const ca = a.codePointAt(i);
      const cb = b.codePointAt(j);
      if (ca !== cb) return ca < cb ? -1 : 1;
      i += ca > 0xffff ? 2 : 1;
      j += cb > 0xffff ? 2 : 1;
    }
    if (i < a.length) return 1;
    if (j < b.length) return -1;
    return 0;
  }

  /* json.dumps(..., ensure_ascii=False): only '"', '\' and code points below 0x20 are escaped. */
  function quote(s) {
    let out = '"';
    for (let k = 0; k < s.length; k++) {
      const c = s.charCodeAt(k);
      if (c === 0x22) out += '\\"';
      else if (c === 0x5c) out += "\\\\";
      else if (c >= 0x20) out += s[k];
      else if (c === 0x0a) out += "\\n";
      else if (c === 0x0d) out += "\\r";
      else if (c === 0x09) out += "\\t";
      else if (c === 0x08) out += "\\b";
      else if (c === 0x0c) out += "\\f";
      else out += "\\u00" + (c < 0x10 ? "0" : "") + c.toString(16);
    }
    return out + '"';
  }

  function serialize(v) {
    if (v === null) return "null";
    if (v === true) return "true";
    if (v === false) return "false";
    if (v instanceof JsonNumber) return v.lexeme;
    if (typeof v === "string") return quote(v);
    if (Array.isArray(v)) return "[" + v.map(serialize).join(",") + "]";
    if (isObject(v)) {
      const keys = Object.keys(v).sort(compareCodePoints);
      return "{" + keys.map(function (k) { return quote(k) + ":" + serialize(v[k]); }).join(",") + "}";
    }
    throw new TypeError("cannot write a " + typeof v + " as receipt JSON");
  }

  /* The bytes the signature covers: the receipt without its top-level "signature", canonical, UTF-8. */
  function canonicalBytes(text) {
    const tree = parse(text);
    if (!isObject(tree)) throw new ReceiptSyntaxError("the receipt is not a JSON object");
    const body = Object.create(null);
    for (const k of Object.keys(tree)) if (k !== "signature") body[k] = tree[k];
    return new TextEncoder().encode(serialize(body));
  }

  /* ------------------------------------------------------------------------------- signature check */

  /* Strict alphabet and padding (like Python's b64decode(validate=True)); null when not base64. */
  function b64decode(s) {
    if (typeof s !== "string" || s.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return null;
    const pad = s.endsWith("==") ? 2 : s.endsWith("=") ? 1 : 0;
    const out = new Uint8Array((s.length / 4) * 3 - pad);
    let o = 0;
    for (let k = 0; k < s.length; k += 4) {
      const q = [0, 1, 2, 3].map(function (x) { const ch = s[k + x]; return ch === "=" ? 0 : B64.indexOf(ch); });
      const word = (q[0] << 18) | (q[1] << 12) | (q[2] << 6) | q[3];
      if (o < out.length) out[o++] = (word >> 16) & 0xff;
      if (o < out.length) out[o++] = (word >> 8) & 0xff;
      if (o < out.length) out[o++] = word & 0xff;
    }
    return out;
  }

  function bytesEqual(a, b) {
    if (a.length !== b.length) return false;
    for (let k = 0; k < a.length; k++) if (a[k] !== b[k]) return false;
    return true;
  }

  function hex(bytes) {
    return Array.from(bytes, function (x) { return x.toString(16).padStart(2, "0"); }).join("");
  }

  function show(v) {
    if (v === undefined) return null;
    if (v instanceof JsonNumber) return v.lexeme;
    if (typeof v === "string") return v;
    return serialize(v);
  }

  function describe(tree) {
    const sig = isObject(tree.signature) ? tree.signature : null;
    const compare = isObject(tree.compare) ? tree.compare : null;
    const counts = compare && isObject(compare.counts) ? compare.counts : null;
    return {
      key_id: sig ? show(sig.key_id) : null,
      key_matches_published: null,
      rehearsal_id: show(tree.rehearsal_id),
      outcome: show(tree.outcome),
      counts: counts ? { predicted: show(counts.predicted), happened: show(counts.happened),
                         surprises: show(counts.surprises) } : null,
      twin_ledger_sha256: show(tree.twin_ledger_sha256),
      prod_ledger_sha256: show(tree.prod_ledger_sha256),
    };
  }

  function notSupported(e) {
    return !!e && e.name === "NotSupportedError";
  }

  /* -> {status: "pass" | "fail" | "unsupported", problems: [...], info: {...}}
     options.subtle replaces globalThis.crypto.subtle (the tests use it to take Ed25519 away). */
  async function verifyReceiptText(text, publishedKeyB64, options) {
    const published = b64decode(publishedKeyB64 == null ? PUBLISHED_KEY : publishedKeyB64);
    if (!published || published.length !== 32) throw new Error("the published key is not 32 bytes of base64");
    const subtle = options && "subtle" in options ? options.subtle
      : (typeof globalThis.crypto !== "undefined" && globalThis.crypto ? globalThis.crypto.subtle : undefined);
    const result = { status: "fail", problems: [], info: {}, signature_checked: false };
    const problems = result.problems;

    let tree;
    try {
      tree = parse(text);
    } catch (e) {
      if (!(e instanceof ReceiptSyntaxError)) throw e;
      problems.push("receipt is not valid JSON: " + e.message);
      return result;
    }
    if (!isObject(tree)) { problems.push("receipt is not a JSON object"); return result; }
    result.info = describe(tree);

    const sig = tree.signature;
    if (!isObject(sig)) { problems.push("receipt has no signature"); return result; }
    if (sig.alg !== "ed25519") {
      problems.push("unsupported signature algorithm " + (sig.alg === undefined ? "none" : serialize(sig.alg)));
      return result;
    }
    const embedded = b64decode(sig.public_key);
    const value = b64decode(sig.value);
    if (!embedded || !value) { problems.push("signature fields are not base64"); return result; }
    if (embedded.length !== 32) { problems.push("embedded public key is not 32 bytes"); return result; }

    const keyMatches = bytesEqual(embedded, published);
    result.info.key_matches_published = keyMatches;

    let bytes;
    try {
      bytes = canonicalBytes(text);
    } catch (e) {
      problems.push("receipt cannot be put in canonical form: " + (e && e.message));
      return result;
    }

    let unsupported = !subtle || typeof subtle.digest !== "function" || typeof subtle.importKey !== "function"
      || typeof subtle.verify !== "function";
    let keyIdOk = false;
    let signatureOk = false;

    if (!unsupported) {
      try {
        const computed = hex(new Uint8Array(await subtle.digest("SHA-256", embedded))).slice(0, 16);
        result.info.key_id_computed = computed;
        keyIdOk = sig.key_id === computed;
        if (!keyIdOk) problems.push("key_id does not match the embedded public key");
      } catch (e) {
        if (notSupported(e)) unsupported = true;
        else problems.push("the key_id could not be checked: " + ((e && e.name) || e));
      }
    }
    if (!keyMatches) problems.push("receipt was signed by a different key than the published one");

    if (!unsupported) {
      try {
        const key = await subtle.importKey("raw", embedded, { name: "Ed25519" }, false, ["verify"]);
        const ok = await subtle.verify({ name: "Ed25519" }, key, value, bytes);
        result.signature_checked = true;
        signatureOk = ok === true;
        if (!signatureOk) problems.push("signature does not match the receipt content");
      } catch (e) {
        if (notSupported(e)) unsupported = true;
        else problems.push("the signature could not be checked: " + ((e && e.name) || e));
      }
    }

    if (unsupported) {
      result.signature_checked = false;
      if (problems.length) {
        problems.push("the signature itself was not checked: this browser has no Ed25519 in WebCrypto");
        result.status = "fail";
      } else {
        result.status = "unsupported";
      }
      return result;
    }
    result.status = signatureOk && keyIdOk && keyMatches && problems.length === 0 ? "pass" : "fail";
    return result;
  }

  /* ------------------------------------------------------------------------ the two tamper buttons */

  function pathString(path) {
    let out = "";
    for (const p of path) {
      if (typeof p === "number") out += "[" + p + "]";
      else if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(p)) out += (out ? "." : "") + p;
      else out += "[" + JSON.stringify(p) + "]";
    }
    return out;
  }

  /* Change one digit of one number in the signed body (compare.counts.happened when present,
     otherwise the first number outside "signature"). One byte of text changes. */
  function changeOneByte(text) {
    const spans = [];
    const tree = parse(text, spans);
    if (!isObject(tree)) throw new Error("the receipt is not a JSON object");
    const numbers = spans.filter(function (s) { return s.kind === "number" && s.path[0] !== "signature"; });
    const target = numbers.find(function (s) {
      return JSON.stringify(s.path) === '["compare","counts","happened"]';
    }) || numbers[0];
    if (!target) throw new Error("the receipt body has no number to change");
    const lexeme = text.slice(target.start, target.end);
    const at = lexeme[0] === "-" ? 1 : 0;
    const digit = lexeme.charCodeAt(at) - 48;
    const next = String(digit === 9 ? 8 : digit + 1);
    const changed = lexeme.slice(0, at) + next + lexeme.slice(at + 1);
    return {
      text: text.slice(0, target.start + at) + next + text.slice(target.start + at + 1),
      path: pathString(target.path), old: lexeme, new: changed,
    };
  }

  /* Replace the first base64 character of signature.value with the next one in the alphabet.
     The first character carries 6 full bits of the signature, so the decoded bytes change while
     the length and padding stay valid. */
  function forgeSignature(text) {
    const spans = [];
    const tree = parse(text, spans);
    if (!isObject(tree)) throw new Error("the receipt is not a JSON object");
    const target = spans.find(function (s) {
      return s.kind === "string" && s.path.length === 2 && s.path[0] === "signature" && s.path[1] === "value";
    });
    if (!target) throw new Error("the receipt has no signature.value");
    const value = tree.signature.value;
    const idx = B64.indexOf(value[0]);
    if (idx < 0) throw new Error("signature.value does not start with a base64 character");
    const replacement = B64[(idx + 1) % 64];
    return {
      text: text.slice(0, target.start) + quote(replacement + value.slice(1)) + text.slice(target.end),
      path: "signature.value", position: 1, old: value[0], new: replacement,
    };
  }

  /* ------------------------------------------------------------------------------------------- page */

  function wire() {
    const $ = function (id) { return document.getElementById(id); };
    const ID_RE = /^[0-9a-z]{1,32}$/;
    const els = {
      form: $("load-form"), rid: $("rid"), load: $("load"), text: $("text"), verify: $("verify"),
      tamper: $("tamper"), forge: $("forge"), note: $("note"), status: $("status"), summary: $("summary"),
      problems: $("problems"), details: $("details"), pubkey: $("pubkey"),
    };
    let generation = 0;
    els.pubkey.textContent = PUBLISHED_KEY;

    function setBusy(busy) {
      for (const b of [els.load, els.verify, els.tamper, els.forge]) b.disabled = busy;
      if (!busy) {
        const empty = !els.text.value.trim();
        els.verify.disabled = empty;
        els.tamper.disabled = empty;
        els.forge.disabled = empty;
      }
    }

    function note(msg, kind) {
      els.note.textContent = msg || "";
      els.note.className = "note" + (kind ? " " + kind : "");
    }

    function clearResult(label) {
      els.status.className = "status idle";
      els.status.textContent = label;
      els.summary.textContent = "";
      els.problems.replaceChildren();
      els.details.replaceChildren();
    }

    function row(term, value, cls) {
      const dt = document.createElement("dt");
      dt.textContent = term;
      const dd = document.createElement("dd");
      dd.textContent = value == null ? "not in the receipt" : value;
      if (cls) dd.className = cls;
      els.details.append(dt, dd);
    }

    function render(r) {
      const labels = { pass: "PASS", fail: "FAIL", unsupported: "Not supported in this browser" };
      els.status.className = "status " + r.status;
      els.status.textContent = labels[r.status];
      if (r.status === "pass") {
        els.summary.textContent = "Signature valid, signed by the published key.";
        if (r.info.outcome === "diverged") {
          els.summary.textContent += " Outcome diverged: production did not do what was rehearsed, "
            + "so a valid signature here is not a success.";
        }
      } else if (r.status === "unsupported") {
        els.summary.textContent = "This browser has no Ed25519 in WebCrypto, so the signature was not checked. "
          + "Use the command in the README instead.";
      } else {
        els.summary.textContent = r.problems.length === 1 ? "1 problem:" : r.problems.length + " problems:";
      }
      els.problems.replaceChildren();
      for (const p of r.status === "pass" ? [] : r.problems) {
        const li = document.createElement("li");
        li.textContent = p;
        els.problems.append(li);
      }
      els.details.replaceChildren();
      const i = r.info || {};
      if (!Object.keys(i).length) return;
      row("key_id", i.key_id);
      row("Signed by the published key",
        i.key_matches_published === true ? "yes" : i.key_matches_published === false ? "no" : "unknown",
        i.key_matches_published === true ? "good" : i.key_matches_published === false ? "bad" : "");
      row("rehearsal_id", i.rehearsal_id);
      row("outcome", i.outcome);
      if (i.counts) {
        row("predicted / happened / surprises",
          [i.counts.predicted, i.counts.happened, i.counts.surprises].map(function (x) {
            return x == null ? "?" : x;
          }).join(" / "));
      }
      row("twin_ledger_sha256", i.twin_ledger_sha256, "mono");
      row("prod_ledger_sha256", i.prod_ledger_sha256, "mono");
    }

    async function check() {
      const mine = ++generation;
      setBusy(true);
      clearResult("Checking…");
      let r;
      try {
        r = await verifyReceiptText(els.text.value, PUBLISHED_KEY);
      } catch (e) {
        r = { status: "fail", problems: ["the check stopped: " + ((e && e.message) || e)], info: {} };
      }
      if (mine === generation) { render(r); setBusy(false); }
      return r;
    }

    async function load(id) {
      if (!ID_RE.test(id)) {
        note("A rehearsal id is 1 to 32 characters: lowercase letters and digits.", "bad");
        return;
      }
      const mine = ++generation;
      setBusy(true);
      note("Loading the receipt of " + id + "…");
      try {
        const res = await fetch("/api/rehearsals/" + id + "/receipt", { cache: "no-store" });
        const body = await res.text();
        if (mine !== generation) return;
        if (!res.ok) {
          setBusy(false);
          note("Could not load the receipt of " + id + ": HTTP " + res.status
            + (res.status === 404 ? " (no such rehearsal, or no receipt yet)." : "."), "bad");
          return;
        }
        els.text.value = body;
        note("Loaded /api/rehearsals/" + id + "/receipt exactly as the server sent it (" + body.length
          + " characters).");
        await check();
      } catch (e) {
        if (mine !== generation) return;
        setBusy(false);
        note("Could not load the receipt of " + id + ": " + ((e && e.message) || e) + ".", "bad");
      }
    }

    function tamper(fn, describeChange) {
      let change;
      try {
        change = fn(els.text.value);
      } catch (e) {
        note("Nothing changed: " + ((e && e.message) || e) + ".", "bad");
        return;
      }
      els.text.value = change.text;
      note(describeChange(change));
      check();
    }

    els.form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      load(els.rid.value.trim());
    });
    els.verify.addEventListener("click", function () { note(""); check(); });
    els.tamper.addEventListener("click", function () {
      tamper(changeOneByte, function (c) {
        return "Changed one byte: " + c.path + " " + c.old + " → " + c.new + ". Checking again.";
      });
    });
    els.forge.addEventListener("click", function () {
      tamper(forgeSignature, function (c) {
        return "Changed character " + c.position + " of " + c.path + ": " + c.old + " → " + c.new
          + ". Checking again.";
      });
    });
    els.text.addEventListener("input", function () {
      generation++;
      note("");
      clearResult("Not checked yet");
      setBusy(false);
    });

    clearResult("Not checked yet");
    setBusy(false);
    const id = new URLSearchParams(window.location.search).get("id");
    if (id !== null) {
      els.rid.value = id;
      load(id);
    }
  }

  const api = {
    PUBLISHED_KEY: PUBLISHED_KEY, JsonNumber: JsonNumber, ReceiptSyntaxError: ReceiptSyntaxError,
    parse: parse, serialize: serialize, canonicalBytes: canonicalBytes, b64decode: b64decode,
    verifyReceiptText: verifyReceiptText, changeOneByte: changeOneByte, forgeSignature: forgeSignature,
  };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  if (typeof document !== "undefined") {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", wire);
    else wire();
  }
})();
