/** @type {import('tsup').Options} */
export default {
	entry: [
		'src/index.ts'
	],
	format: ['esm', 'cjs'],
	dts: true,
	clean: false,
	splitting: false,
	platform: 'browser',
	minify: 'terser',
	bundle: false,
}