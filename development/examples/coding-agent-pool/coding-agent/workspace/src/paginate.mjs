// Number of pages needed for `total` items at `perPage` items per page.
export function pageCount(total, perPage) {
  return Math.floor(total / perPage);
}
