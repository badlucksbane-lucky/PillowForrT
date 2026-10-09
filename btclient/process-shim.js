// WebTorrent and a few of its dependencies read `process` (process.browser, process.nextTick); there is none in a browser.
export const process = {
  browser: true,
  env: {},
  platform: 'browser',
  version: '',
  versions: {},
  argv: [],
  cwd: () => '/',
  nextTick: (fn, ...args) => queueMicrotask(() => fn(...args))
}
