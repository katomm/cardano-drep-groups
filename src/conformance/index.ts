// Public surface of drep-groups/conformance: the seeded chain and schedule generators and
// the schedule driver that checks a Store against replay.
export { type ChainOptions, generateChain, generateSchedule, type ScheduleOptions, type ScheduleStep } from './generate.js';
export {
  assertEquivalent, ConformanceError, type Coverage, type DisplayProjection, type DriverStore, emptyCoverage,
  engineProjection, mergeCoverage, replayProjection, runSchedule, type ScheduleResult,
} from './driver.js';
