import type { Commit, CommitRange, HashOpening, RevealOutput } from 'tlsn-wasm';

/**
 * One hash commitment, opened: the committed range, the commitment, and what
 * opens it (the plaintext and the blinder). All byte strings are hex.
 *
 * Holding an opening lets the caller prove statements about the committed
 * plaintext later (for example inside a zero-knowledge circuit) without
 * rerunning MPC-TLS and without revealing the plaintext to the verifier.
 */
export interface CommitmentOpening {
  start: number;
  end: number;
  algorithm: CommitRange['algorithm'];
  hash: string;
  blinder: string;
  plaintext: string;
}

export interface CommitmentOpenings {
  sent: CommitmentOpening[];
  recv: CommitmentOpening[];
}

const toHex = (bytes: ArrayLike<number>) =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

async function sha256Hex(data: Uint8Array<ArrayBuffer>): Promise<string> {
  return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', data)));
}

/**
 * Pairs each committed range with its opening.
 *
 * `RevealOutput` documents its openings as being in `Commit` input order, but
 * in practice they can come back in another order (e.g. by byte offset), which
 * would attach one range's hash and blinder to another range's plaintext. For
 * SHA-256 ranges the right opening is the one where
 * SHA256(plaintext || blinder) == hash, so match on that; other algorithms
 * (not available in WebCrypto) keep the positional pairing.
 */
async function openRanges(
  ranges: CommitRange[],
  openings: HashOpening[],
  bytes: Uint8Array,
): Promise<CommitmentOpening[]> {
  const unused = openings.map((o, i) => ({ ...o, i }));
  const result: CommitmentOpening[] = [];
  for (const [i, range] of ranges.entries()) {
    const plaintext = bytes.subarray(range.start, range.end);
    let match: (typeof unused)[number] | undefined;
    if (range.algorithm === 'SHA256') {
      for (const candidate of unused) {
        const data = new Uint8Array(plaintext.length + candidate.blinder.length);
        data.set(plaintext);
        data.set(candidate.blinder, plaintext.length);
        if ((await sha256Hex(data)) === toHex(candidate.hash)) {
          match = candidate;
          break;
        }
      }
    } else {
      match = unused.find((o) => o.i === i);
    }
    if (!match) {
      throw new Error(`No hash commitment opening matches range ${range.start}..${range.end}`);
    }
    unused.splice(unused.indexOf(match), 1);
    result.push({
      start: range.start,
      end: range.end,
      algorithm: range.algorithm,
      hash: toHex(match.hash),
      blinder: toHex(match.blinder),
      plaintext: toHex(plaintext),
    });
  }
  return result;
}

/** The openings of every hash-committed range in `commit`, against the transcript. */
export async function commitmentOpenings(
  commit: Commit,
  openings: RevealOutput,
  sentBytes: Uint8Array,
  recvBytes: Uint8Array,
): Promise<CommitmentOpenings> {
  return {
    sent: await openRanges(commit.sent, openings.sent, sentBytes),
    recv: await openRanges(commit.recv, openings.recv, recvBytes),
  };
}
