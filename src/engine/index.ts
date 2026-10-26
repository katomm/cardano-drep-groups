// Public surface of the incremental engine.
export * from './types.js';
export { RETENTION_FLOOR, classifyNewInput, foreignJoinRefs, mergeRecovery } from './classify.js';
export { routeTx } from './route.js';
export { LazyWorld, stageKeys, type Step } from './lazyWorld.js';
export { applyControl, type RuleObserver, txContextOf } from './control.js';
export { applyCredential } from './credential.js';
export { type EngineSnapshot, MemoryStore } from './memoryStore.js';
export { type RunOptions, runEngine } from './run.js';
