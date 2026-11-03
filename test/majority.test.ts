import { describe, expect, it } from 'vitest';
import { EncodeError } from '../src/encode.js';
import { majorityScript } from '../src/majority.js';
import { evaluateNativeScript } from '../src/nativeScript.js';
import { K } from './helpers.js';

const A = K(1);
const B = K(2);
const C = K(3);
const ctx = (...signers: string[]) => ({ signers: new Set(signers), invalidBefore: null, invalidHereafter: null });

describe('majorityScript', () => {
  it('gives the same hash for the same set in any order', () => {
    expect(majorityScript([B, A, C], 2).hash).toBe(majorityScript([C, B, A], 2).hash);
  });

  it('dedupes keys before checking the threshold', () => {
    expect(() => majorityScript([A, A], 2)).toThrow(EncodeError);
    expect(majorityScript([A, A.toUpperCase(), B], 2).keys).toEqual([A, B]);
  });

  it('refuses thresholds of 0 and above k', () => {
    expect(() => majorityScript([A], 0)).toThrow(EncodeError);
    expect(() => majorityScript([A], 2)).toThrow(EncodeError);
  });

  it('refuses an empty key list and malformed keys', () => {
    expect(() => majorityScript([], 1)).toThrow(EncodeError);
    expect(() => majorityScript(['abcd'], 1)).toThrow(EncodeError);
  });

  it('is satisfied by exactly n of the keys', () => {
    const { script } = majorityScript([A, B, C], 2);
    expect(evaluateNativeScript(script, ctx(A))).toBe(false);
    expect(evaluateNativeScript(script, ctx(A, C))).toBe(true);
  });
});
