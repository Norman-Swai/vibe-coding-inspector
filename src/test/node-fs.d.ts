// @types/node is not a dependency: this declares the one Node call the stylesheet test reads styles.css with.
declare module 'node:fs' {
  export function readFileSync(path: string, encoding: 'utf8'): string;
}
