import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';
import eslintPluginPrettierRecommended from 'eslint-plugin-prettier/recommended';
import globals from 'globals';

export default tseslint.config(
    {
        ignores: [
            "dist",
            ".yarn",
            "jest.config.ts",
            "eslint.config.mjs",
            "node_modules",
            "test",
        ],
    },
    {
        languageOptions: {
            globals: globals.node,
            parserOptions: {
                project: "./tsconfig.json",
                tsconfigDirName: import.meta.dirname,
            },
        },
        linterOptions: {
            reportUnusedDisableDirectives: "warn",
        },
        rules: {
            "@typescript-eslint/explicit-function-return-type": "error",
        },
    },
    {
        // Once we remove the legacy tests in ./test, we can remove these JS-specific rules
        files: ["test/**/*.ts"],
        ...tseslint.configs.disableTypeChecked,
        rules: {
            ...tseslint.configs.disableTypeChecked.rules,
            "@typescript-eslint/explicit-function-return-type": "off",
            "@typescript-eslint/no-var-requires": "off",
            "@typescript-eslint/no-unused-vars": "off",
        },
    },
    eslint.configs.recommended,
    ...tseslint.configs.strictTypeChecked,
    eslintPluginPrettierRecommended,
);
