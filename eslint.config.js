// Configuração do ESLint (formato "flat", padrão do ESLint 9+).
// Ele verifica seu código sem rodar — pega erros que Node só descobriria em runtime,
// tipo função não importada, variável não usada, uso de variável antes de declarar.

import js from '@eslint/js';
import globals from 'globals';

export default [
	// Preset "recomendado" oficial do ESLint: regras que quase todo projeto quer.
	js.configs.recommended,

	{
		languageOptions: {
			ecmaVersion: 'latest',      // aceita sintaxe moderna (top-level await, etc.)
			sourceType: 'module',       // trata arquivos como ES Modules (import/export)
			globals: {
				...globals.node,         // reconhece globals do Node: console, process, fetch, ...
			},
		},

		rules: {
			// Deixe como warning pra não travar o desenvolvimento; vira erro depois.
			'no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
			'no-console': 'off',  // scanner É um CLI, faz console.log o tempo todo
		},
	},

	// Ignora pastas que não devem ser analisadas
	{
		ignores: ['node_modules/**', 'relatorios/**'],
	},
];
