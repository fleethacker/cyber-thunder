import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

/** Each fixture has its own module cache, including real runtime session metadata. */
export function createModuleLoader() {
  const cache = new Map();
  function evaluate(url, imports = {}) {
    const key = url.href;
    if (cache.has(key)) return cache.get(key);
    const exports = {};
    cache.set(key, exports);
    const require = createRequire(url);
    const resolve = (name) => {
      if (Object.hasOwn(imports, name)) return imports[name];
      if (!name.startsWith('.')) return require(name);
      const base = new URL(name, url);
      const resolved = ['', '.ts', '.tsx', '.js', '/index.ts', '/index.tsx']
        .map((suffix) => new URL(base.href + suffix)).find((candidate) => existsSync(candidate) && /\.[cm]?[jt]sx?$/.test(candidate.pathname));
      if (!resolved) throw new Error(`Cannot resolve ${name} from ${fileURLToPath(url)}`);
      if (/\.[cm]?js$/.test(resolved.pathname)) return require(fileURLToPath(resolved));
      return evaluate(resolved);
    };
    try {
      const { outputText } = ts.transpileModule(readFileSync(url, 'utf8'), {
        fileName: fileURLToPath(url), compilerOptions: {
          module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020, jsx: ts.JsxEmit.ReactJSX,
        },
      });
      new Function('require', 'exports', outputText)(resolve, exports);
      return exports;
    } catch (error) { cache.delete(key); throw error; }
  }
  return evaluate;
}

export const evaluate = (url, imports = {}) => createModuleLoader()(url, imports);
