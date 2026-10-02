import { describe, it, expect } from 'vitest';
import type { Commit, RevealOutput } from 'tlsn-wasm';
import { commitmentOpenings } from '../../src/offscreen/commitmentOpenings';

const enc = (s: string) => new TextEncoder().encode(s);
const hex = (b: ArrayLike<number>) =>
  Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

async function sha256(data: Uint8Array): Promise<number[]> {
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', data)));
}

/** A received transcript with two committed fields, and their real openings. */
async function fixture() {
  const recv = enc('{"result":{"id":"S1234567D","phone":"91234567"}}');
  const text = new TextDecoder().decode(recv);
  const range = (needle: string) => {
    const start = text.indexOf(needle);
    return { start, end: start + needle.length, algorithm: 'SHA256' as const };
  };
  const id = range('"id":"S1234567D"');
  const phone = range('"phone":"91234567"');
  const open = async (r: { start: number; end: number }, fill: number) => {
    const blinder = Array(16).fill(fill);
    const data = new Uint8Array([...recv.subarray(r.start, r.end), ...blinder]);
    return { hash: await sha256(data), blinder };
  };
  return { recv, id, phone, idOpening: await open(id, 1), phoneOpening: await open(phone, 2) };
}

describe('commitmentOpenings', () => {
  it('returns each range with its plaintext, hash and blinder', async () => {
    const f = await fixture();
    const commit: Commit = { sent: [], recv: [f.id, f.phone] };
    const openings = { sent: [], recv: [f.idOpening, f.phoneOpening] } as RevealOutput;
    const out = await commitmentOpenings(commit, openings, new Uint8Array(), f.recv);
    expect(out.sent).toEqual([]);
    expect(out.recv).toEqual([
      {
        ...f.id,
        hash: hex(f.idOpening.hash),
        blinder: hex(f.idOpening.blinder),
        plaintext: hex(enc('"id":"S1234567D"')),
      },
      {
        ...f.phone,
        hash: hex(f.phoneOpening.hash),
        blinder: hex(f.phoneOpening.blinder),
        plaintext: hex(enc('"phone":"91234567"')),
      },
    ]);
  });

  it('pairs SHA-256 openings by hash when they come back in another order', async () => {
    const f = await fixture();
    const commit: Commit = { sent: [], recv: [f.id, f.phone] };
    const swapped = { sent: [], recv: [f.phoneOpening, f.idOpening] } as RevealOutput;
    const out = await commitmentOpenings(commit, swapped, new Uint8Array(), f.recv);
    expect(out.recv[0].blinder).toBe(hex(f.idOpening.blinder));
    expect(out.recv[1].blinder).toBe(hex(f.phoneOpening.blinder));
  });

  it('keeps positional pairing for algorithms WebCrypto lacks', async () => {
    const f = await fixture();
    const blake = { ...f.id, algorithm: 'BLAKE3' as const };
    const opening = { hash: Array(32).fill(9), blinder: Array(16).fill(3) };
    const out = await commitmentOpenings(
      { sent: [], recv: [blake] },
      { sent: [], recv: [opening] } as RevealOutput,
      new Uint8Array(),
      f.recv,
    );
    expect(out.recv[0].hash).toBe(hex(opening.hash));
  });

  it('throws when no opening matches a SHA-256 range', async () => {
    const f = await fixture();
    const wrong = {
      sent: [],
      recv: [{ hash: Array(32).fill(0), blinder: Array(16).fill(0) }],
    } as RevealOutput;
    await expect(
      commitmentOpenings({ sent: [], recv: [f.id] }, wrong, new Uint8Array(), f.recv),
    ).rejects.toThrow(/No hash commitment opening matches range/);
  });
});
