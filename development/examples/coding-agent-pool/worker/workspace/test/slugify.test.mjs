import { test } from "node:test";
import assert from "node:assert/strict";
import { slugify } from "../src/slugify.mjs";

test("slugify collapses runs of separators and trims them", () => {
  assert.equal(slugify("  Hello,  World!  "), "hello-world");
  assert.equal(slugify("Rate & Term"), "rate-term");
});
