module.exports = {
    "env": {
        "browser": true,
        "es2021": true
    },
    "extends": ['airbnb-base', 'prettier'],
    "parser": '@typescript-eslint/parser', // specifies the ESLint parser
    "overrides": [
        {
            "env": {
                "node": true
            },
            "files": [
                ".eslintrc.{js,cjs}"
            ],
            "parserOptions": {
                "sourceType": "script"
            }
        }
    ],
    "ignorePatterns": [".eslintrc.js", "**/*.test.js", "**/*.config.js"],
    "parserOptions": {
        "ecmaVersion": "latest",
        "sourceType": "module",
        "project": './tsconfig.json', // specify the path to your tsconfig.json file
    },
    "plugins": ['prettier'],
    "rules": {
        'prettier/prettier': 'error',
        'no-console': 'off',
        "import/extensions": [
            "error",
            "ignorePackages",
            {
                "js": "never",
                "jsx": "never",
                "ts": "never",
                "tsx": "never"
            }
        ],
    },
    "settings": {
        "import/resolver": {
            "node": {
                "extensions": [".js", ".jsx", ".ts", ".tsx"]
            }
        }
    },
}
