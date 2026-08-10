import { test } from "node:test";
import assert from "node:assert/strict";
import { pageCount } from "../src/paginate.mjs";

test("pageCount rounds up for a partial last page", () => {
  assert.equal(pageCount(25, 10), 3);
  assert.equal(pageCount(20, 10), 2);
  assert.equal(pageCount(0, 10), 0);
});
