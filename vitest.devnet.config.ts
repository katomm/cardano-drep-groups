import { defineConfig } from 'vitest/config';

// Devnet tests start cardano-node, Kupo and Ogmios in Docker through
// @evolution-sdk/devnet. They run only through `npm run test:devnet`, never
// in the default suite, so `npm test` never needs Docker.
export default defineConfig({
  test: {
    name: 'devnet',
    environment: 'node',
    include: ['test/devnet/**/*.devnet.test.ts'],
    testTimeout: 300_000,
    hookTimeout: 300_000,
    fileParallelism: false,
  },
});
