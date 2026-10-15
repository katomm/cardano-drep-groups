import { configDefaults, defineConfig } from 'vitest/config';

// The devnet suite needs Docker and runs only through `npm run test:devnet`.
export default defineConfig({ test: { include: ['test/**/*.test.ts'], exclude: [...configDefaults.exclude, 'test/devnet/**'] } });
