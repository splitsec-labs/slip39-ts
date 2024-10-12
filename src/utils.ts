import { getRandomValues } from "uncrypto";

import { RADIX_BITS } from "./constants";

const BIGINT_WORD_BITS = BigInt(8);

export function generateArray<T>(
  arr: (T | number)[],
  n: number,
  v?: (idx: number) => T,
): (number | T)[] {
  const m = n || arr.length;
  for (let i = 0; i < m; i++) {
    arr.push(typeof v === "undefined" ? i : v(i));
  }
  return arr;
}

export function encodeHexString(s: string): number[] {
  const bytes = [];
  for (let i = 0; i < s.length; ++i) {
    bytes.push(s.charCodeAt(i));
  }
  return bytes;
}

export function decodeHexString(s: number[]): string {
  const str: string[] = [];
  const hex = s.toString().split(",");
  for (let i = 0; i < hex.length; i++) {
    str.push(String.fromCharCode(Number(hex[i])));
  }
  return str.toString().replace(/,/g, "");
}

export function bitsToBytes(n: number): number {
  return Math.floor((n + 7) / 8);
}

export function bitsToWords(n: number): number {
  return Math.floor((n + RADIX_BITS - 1) / RADIX_BITS);
}

export function randomBytes(length = 32): number[] {
  const randoms = new Uint8Array(length);
  getRandomValues(randoms);
  return Array.from(randoms);
}

export function listsAreEqual(
  a: null | unknown[],
  b: null | unknown[],
): boolean {
  if (a === null || b === null || a.length !== b.length) {
    return false;
  }

  let i = 0;
  return a.every((item) => {
    return b[i++] === item;
  });
}

export function decodeBigInt(bytes: number[]): bigint {
  let result = BigInt(0);
  for (let i = 0; i < bytes.length; i++) {
    const b = BigInt(bytes[bytes.length - i - 1]);
    result += b << (BIGINT_WORD_BITS * BigInt(i));
  }
  return result;
}

export function encodeBigInt(number: bigint, paddedLength = 0): number[] {
  const BYTE_MASK = BigInt(0xff);
  const BIGINT_ZERO = BigInt(0);
  const result: number[] = [];

  while (number > BIGINT_ZERO) {
    result.unshift(Number(number & BYTE_MASK));
    number >>= BIGINT_WORD_BITS;
  }

  // Zero padding to the length
  for (let i = result.length; i < paddedLength; i++) {
    result.unshift(0);
  }

  if (paddedLength !== 0 && result.length > paddedLength) {
    throw new Error(
      `Error in encoding BigInt value, expected less than ${String(paddedLength)} length value, got ${String(result.length)}`,
    );
  }

  return result;
}
