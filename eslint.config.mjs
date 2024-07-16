import neostandard from 'neostandard';

export default [
  ...neostandard({ noStyle: true, ts: true }),
  {
    files: ['src/**/*.ts'],
    rules: {
      'linebreak-style': ['error', 'unix'],
      'no-console': 'error',
      'no-shadow': 'error',
    },
  },
];
