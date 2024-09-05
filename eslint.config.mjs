import pluginJs from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";

export default [
  {
    ignores: ["**/node_modules/**", "**/dist/", "**/build/**"],
  },
  {
    plugins: {
      "@typescript-eslint": tseslint.plugin,
    },
  },
  { files: ["src/**/*.{js,mjs,cjs,ts}"] },
  {
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.node,
      },
    },
  },
  pluginJs.configs.recommended,
  ...tseslint.configs.recommended,
  // ...tseslint.configs.strict,

  {
    rules: {
      "no-unused-vars": "warn",
      "no-undef": "error",
      "no-console": "warn",
      "prefer-const": "error",
    },
  },
];
