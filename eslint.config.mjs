import neostandard from 'neostandard';

export default [
	...neostandard({ noStyle: true }),
	{
		files: ['lib/**/*.js', 'test/**/*.js'],
		rules: {
			'linebreak-style': ['error', 'unix'],
			'no-console': 'error',
			'no-shadow': 'error',
			'no-unused-vars': [
				'error',
				{
					args: 'after-used',
					argsIgnorePattern: '^ignore$',
					caughtErrors: 'none',
					ignoreRestSiblings: true,
					vars: 'all',
				},
			],
		},
	},
];
