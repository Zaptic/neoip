import tsc from '@rollup/plugin-typescript';
import { rimraf } from 'rimraf';

rimraf.sync('dist');

const production = process.env.ROLLUP_WATCH !== 'true';
const tsconfig = production ? 'tsconfig.build.json' : 'tsconfig.json';

export default {
  input: 'src/ip.ts',
  external: ['node:net', 'node:os', 'node:buffer'],
  output: [
    {
      generatedCode: 'es2015',
      file: 'dist/ip.cjs',
      format: 'cjs',
    },
    {
      generatedCode: 'es2015',
      file: 'dist/ip.mjs',
      format: 'esm',
    },
  ],
  plugins: [tsc({ tsconfig })],
};
