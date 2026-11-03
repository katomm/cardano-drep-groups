import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

type Term = string | { '@id': string; '@context'?: Record<string, Term> };
const ctx = (JSON.parse(readFileSync(new URL('../context/drep-groups-v1.jsonld', import.meta.url), 'utf8')) as {
  '@context': Record<string, Term>;
})['@context'];

const BASE = 'https://github.com/katomm/cardano-drep-groups/blob/main/context/drep-groups-v1.jsonld#';

function nested(t: Term | undefined): Record<string, Term> {
  if (typeof t === 'object' && t['@context']) return t['@context'];
  throw new Error('term has no nested context');
}

describe('JSON-LD context', () => {
  it('declares the language, the hash algorithm and the body', () => {
    expect(ctx['@language']).toBe('en-us');
    expect(ctx.hashAlgorithm).toBeDefined();
    expect(ctx.body).toBeDefined();
  });

  it('defines a term under the context IRI for every profile field', () => {
    const body = nested(ctx.body);
    const paymentAddresses = nested(body.paymentAddresses);
    for (const [scope, fields] of [
      [body, ['name', 'description', 'website', 'image', 'charter', 'paymentAddresses']],
      [paymentAddresses, ['address', 'purpose', 'treasuryScript']],
    ] as const) {
      for (const f of fields) {
        const t = scope[f];
        const id = typeof t === 'string' ? t : t?.['@id'];
        expect(id, f).toBe(`DRG:${f}`);
      }
    }
    expect(ctx.DRG).toBe(BASE);
  });
});
