type LogArgs = unknown[];

const logger = {
  log: (...args: LogArgs) => console.log('[LOG]', ...args),
  info: (...args: LogArgs) => console.log('[INFO]', ...args),
  warn: (...args: LogArgs) => console.log('[WARN]', ...args),
  error: (...args: LogArgs) => console.log('[ERROR]', ...args),
};

export { logger }
