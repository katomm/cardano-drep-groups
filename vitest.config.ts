import { configDefaults, defineConfig } from 'vitest/config';

// The devnet suite needs Docker and runs only through `npm run test:devnet`.
// The randomized cborSpan differential runs for seconds, so the timeout leaves
// room for parallel workers on a busy machine.
export default defineConfig({
  test: { include: ['test/**/*.test.ts'], exclude: [...configDefaults.exclude, 'test/devnet/**'], testTimeout: 30_000 },
});
