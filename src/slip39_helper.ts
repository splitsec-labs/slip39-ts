import { subtle } from "uncrypto";

import {
  CHECKSUM_WORDS_LENGTH,
  CUSTOMIZATION_STRING_EXTENDABLE,
  CUSTOMIZATION_STRING_NON_EXTENDABLE,
  DIGEST_INDEX,
  DIGEST_LENGTH,
  EXP_TABLE,
  EXTENDABLE_BACKUP_FLAG_BITS_LENGTH,
  ID_BITS_LENGTH,
  ITERATION_COUNT,
  ITERATION_EXP_BITS_LENGTH,
  ITERATION_EXP_WORDS_LENGTH,
  LOG_TABLE,
  MAX_ITERATION_EXP,
  MAX_SHARE_COUNT,
  METADATA_WORDS_LENGTH,
  MNEMONICS_WORDS_LENGTH,
  RADIX_BITS,
  ROUND_COUNT,
  SECRET_INDEX,
  WORD_LIST,
  WORD_LIST_MAP,
} from "./constants";
import { IDecodedMnemonic, IDecodedMnemonics } from "./interfaces";
import {
  bitsToBytes,
  bitsToWords,
  decodeBigInt,
  encodeBigInt,
  encodeHexString,
  generateArray,
  listsAreEqual,
  randomBytes,
} from "./utils";

//
// The round function used internally by the Feistel cipher.
//
async function roundFunction(
  round: number,
  passphrase: number[],
  exp: number,
  salt: number[],
  secret: number[],
): Promise<number[]> {
  const saltedSecret = salt.concat(secret);
  const roundedPhrase = [round].concat(passphrase);
  const iterations = (ITERATION_COUNT << exp) / ROUND_COUNT;

  return subtle
    .importKey("raw", Buffer.from(roundedPhrase), "PBKDF2", false, [
      "deriveBits",
    ])
    .then((key) => {
      return subtle.deriveBits(
        {
          name: "PBKDF2",
          hash: "SHA-256",
          salt: Buffer.from(saltedSecret),
          iterations: iterations,
        },
        key,
        secret.length * 8,
      );
    })
    .then((derived: ArrayBuffer) => {
      // TODO: Can we use a Uint8Array instead of a Buffer here?
      return Array.prototype.slice.call(Buffer.from(derived), 0);
    });
}

export async function crypt(
  masterSecret: number[],
  passphrase: string,
  iterationExponent: number,
  identifier: number[],
  extendableBackupFlag: number,
  encrypt = true,
): Promise<number[]> {
  // Iteration exponent validated here.
  if (iterationExponent < 0 || iterationExponent > MAX_ITERATION_EXP) {
    throw Error(
      `Invalid iteration exponent (${String(iterationExponent)}). Expected between 0 and ${String(MAX_ITERATION_EXP)}`,
    );
  }

  let IL = masterSecret.slice().slice(0, masterSecret.length / 2);
  let IR = masterSecret.slice().slice(masterSecret.length / 2);

  const pwd = encodeHexString(passphrase);

  const salt = getSalt(identifier, extendableBackupFlag);

  let range = generateArray([], ROUND_COUNT);
  range = encrypt ? range : range.reverse();

  for (const round of range) {
    const f = await roundFunction(round, pwd, iterationExponent, salt, IR);
    const t = xor(IL, f);
    IL = IR;
    IR = t;
  }
  return IR.concat(IL);
}

export async function createDigest(
  randomData: number[],
  sharedSecret: number[],
): Promise<number[]> {
  return subtle
    .importKey(
      "raw",
      new Uint8Array(randomData),
      {
        name: "HMAC",
        hash: { name: "SHA-256" },
      },
      false,
      ["sign"],
    )
    .then(async (key) => {
      let signature = await subtle.sign(
        "HMAC",
        key,
        new Uint8Array(sharedSecret),
      );
      signature = signature.slice(0, 4);
      return Array.prototype.slice.call(Buffer.from(signature), 0);
    });
}

export async function splitSecret(
  threshold: number,
  shareCount: number,
  sharedSecret: number[],
): Promise<number[][]> {
  if (threshold <= 0) {
    throw Error(
      `The requested threshold (${String(threshold)}) must be a positive integer.`,
    );
  }

  if (threshold > shareCount) {
    throw Error(
      `The requested threshold (${String(threshold)}) must not exceed the number of shares (${String(shareCount)}).`,
    );
  }

  if (shareCount > MAX_SHARE_COUNT) {
    throw Error(
      `The requested number of shares (${String(shareCount)}) must not exceed ${String(MAX_SHARE_COUNT)}.`,
    );
  }
  //  If the threshold is 1, then the digest of the shared secret is not used.
  if (threshold === 1) {
    return generateArray([], shareCount, () => sharedSecret) as number[][];
  }

  const randomShareCount = threshold - 2;

  const randomPart = randomBytes(sharedSecret.length - DIGEST_LENGTH);
  const digest = await createDigest(randomPart, sharedSecret);

  const baseShares = new Map<number, number[]>();
  let shares: number[][] = [];
  if (randomShareCount) {
    shares = generateArray([], randomShareCount, () =>
      randomBytes(sharedSecret.length),
    ) as number[][];
    shares.forEach((item: number[], idx: number) => {
      baseShares.set(idx, item);
    });
  }
  baseShares.set(DIGEST_INDEX, digest.concat(randomPart));
  baseShares.set(SECRET_INDEX, sharedSecret);

  for (let i = randomShareCount; i < shareCount; i++) {
    const rr = interpolate(baseShares, i);
    shares.push(rr);
  }

  return shares;
}

//
// Returns a randomly generated integer in the range 0, ..., 2**ID_BITS_LENGTH - 1.
//
export function generateIdentifier(): number[] {
  const byte = bitsToBytes(ID_BITS_LENGTH);
  const bits = ID_BITS_LENGTH % 8;
  const identifier = randomBytes(byte);

  identifier[0] = identifier[0] & ((1 << bits) - 1);

  return identifier;
}

function xor(a: number[], b: number[]): number[] {
  if (a.length !== b.length) {
    throw new Error(
      `Invalid padding in mnemonic or insufficient length of mnemonics (${String(a.length)} or ${String(b.length)})`,
    );
  }
  return generateArray([], a.length, (i) => a[i] ^ b[i]);
}

function getSalt(identifier: number[], extendableBackupFlag: number): number[] {
  if (extendableBackupFlag) {
    return [];
  } else {
    const salt = encodeHexString(CUSTOMIZATION_STRING_NON_EXTENDABLE);
    return salt.concat(identifier);
  }
}

function interpolate(shares: Map<number, number[]>, x: number): number[] {
  const xCoord = new Set(shares.keys());
  const arr = Array.from(shares.values(), (v) => v.length);
  const sharesValueLengths = new Set(arr);

  if (sharesValueLengths.size !== 1) {
    throw new Error(
      "Invalid set of shares. All share values must have the same length.",
    );
  }

  if (xCoord.has(x)) {
    shares.forEach((v: number[], k: number): number[] => {
      if (k === x) {
        return v;
      }
      throw new Error(
        "Invalid set of shares. All share values must have the same length.",
      );
    });
  }

  // Logarithm of the product of (x_i - x) for i = 1, ... , k.
  let logProd = 0;

  shares.forEach((_, k: number) => {
    logProd = logProd + LOG_TABLE[k ^ x];
  });

  const results = generateArray(
    [],
    sharesValueLengths.values().next().value,
    () => 0,
  );

  shares.forEach((v: number[], k: number) => {
    // The logarithm of the Lagrange basis polynomial evaluated at x.
    let sum = 0;
    shares.forEach((_, kk: number) => {
      sum = sum + LOG_TABLE[k ^ kk];
    });

    // FIXME: -18 % 255 = 237. IT shoulud be 237 and not -18 as it's
    // implemented in javascript.
    const basis = (logProd - LOG_TABLE[k ^ x] - sum) % 255;

    const logBasisEval = basis < 0 ? 255 + basis : basis;

    v.forEach((item, idx) => {
      const shareVal = item;
      const intermediateSum = results[idx];
      const r =
        shareVal !== 0
          ? EXP_TABLE[(LOG_TABLE[shareVal] + logBasisEval) % 255]
          : 0;

      results[idx] = intermediateSum ^ r;
    });
  });
  return results;
}

function rs1024Polymod(data: number[]): number {
  const GEN = [
    0xe0e040, 0x1c1c080, 0x3838100, 0x7070200, 0xe0e0009, 0x1c0c2412,
    0x38086c24, 0x3090fc48, 0x21b1f890, 0x3f3f120,
  ];
  let chk = 1;

  data.forEach((byte) => {
    const b = chk >> 20;
    chk = ((chk & 0xfffff) << 10) ^ byte;

    for (let i = 0; i < 10; i++) {
      const gen = ((b >> i) & 1) !== 0 ? GEN[i] : 0;
      chk = chk ^ gen;
    }
  });

  return chk;
}

function get_customization_string(
  extendableBackupFlag: number,
): "shamir" | "shamir_extendable" {
  return extendableBackupFlag
    ? CUSTOMIZATION_STRING_EXTENDABLE
    : CUSTOMIZATION_STRING_NON_EXTENDABLE;
}

function rs1024CreateChecksum(
  data: number[],
  extendableBackupFlag: number,
): number[] {
  const values = encodeHexString(get_customization_string(extendableBackupFlag))
    .concat(data)
    .concat(generateArray([], CHECKSUM_WORDS_LENGTH, () => 0));
  const polymod = rs1024Polymod(values) ^ 1;
  return generateArray(
    [],
    CHECKSUM_WORDS_LENGTH,
    (i) => (polymod >> (10 * i)) & 1023,
  ).reverse();
}

function rs1024VerifyChecksum(
  data: number[],
  extendableBackupFlag: number,
): boolean {
  return (
    rs1024Polymod(
      encodeHexString(get_customization_string(extendableBackupFlag)).concat(
        data,
      ),
    ) === 1
  );
}

//
// Converts a list of base 1024 indices in big endian order to an integer value.
//
export function intFromIndices(indices: number[]): bigint {
  let value = BigInt(0);
  const radix = BigInt(Math.pow(2, RADIX_BITS));
  indices.forEach((index) => {
    value = value * radix + BigInt(index);
  });

  return value;
}

//
// Converts a Big integer value to indices in big endian order.
//
function intToIndices(value: bigint, length: number, bits: number): number[] {
  const mask = BigInt((1 << bits) - 1);
  const result = generateArray([], length, (i) =>
    Number((value >> (BigInt(i) * BigInt(bits))) & mask),
  );
  return result.reverse();
}

export function mnemonicFromIndices(indices: number[]): string {
  const result = indices.map((index) => {
    return WORD_LIST[index];
  });
  return result.toString().split(",").join(" ");
}

export function mnemonicToIndices(mnemonic: string): number[] {
  const words = mnemonic.toLowerCase().split(" ");
  return words.reduce((prev: number[], item) => {
    const index = WORD_LIST_MAP[item];
    if (typeof index === "undefined") {
      throw new Error(`Invalid mnemonic word ${item}.`);
    }
    return prev.concat(index);
  }, []);
}

export async function recoverSecret(
  threshold: number,
  shares: Map<number, number[]>,
): Promise<number[]> {
  // If the threshold is 1, then the digest of the shared secret is not used.
  if (threshold === 1) {
    return shares.values().next().value;
  }

  const sharedSecret = interpolate(shares, SECRET_INDEX);
  const digestShare = interpolate(shares, DIGEST_INDEX);
  const digest = digestShare.slice(0, DIGEST_LENGTH);
  const randomPart = digestShare.slice(DIGEST_LENGTH);

  const recoveredDigest = await createDigest(randomPart, sharedSecret);
  if (!listsAreEqual(digest, recoveredDigest)) {
    throw new Error("Invalid digest of the shared secret.");
  }
  return sharedSecret;
}

//
// Combines mnemonic shares to get the master secret, which was previously
// split using Shamir's secret sharing scheme.
//
export async function combineMnemonics(
  mnemonics: string[],
  passphrase = "",
): Promise<number[]> {
  if (mnemonics.length === 0) {
    throw new Error("The list of mnemonics is empty.");
  }

  const decoded = decodeMnemonics(mnemonics);
  const identifier = decoded.identifier;
  const extendableBackupFlag = decoded.extendableBackupFlag;
  const iterationExponent = decoded.iterationExponent;
  const groupThreshold = decoded.groupThreshold;
  const groupCount = decoded.groupCount;
  const groups = decoded.groups;

  if (groups.size < groupThreshold) {
    throw new Error(
      `Insufficient number of mnemonic groups (${String(groups.size)}). The required number of groups is ${String(groupThreshold)}.`,
    );
  }

  if (groups.size !== groupThreshold) {
    throw new Error(
      `Wrong number of mnemonic groups. Expected ${String(groupThreshold)} groups, but ${String(groups.size)} were provided.`,
    );
  }

  const allShares = new Map<number, number[]>();
  for (const [groupIndex, members] of groups.entries()) {
    const threshold = members.keys().next().value;
    const shares = members.values().next().value;
    if (shares.size !== threshold) {
      const prefix = groupPrefix(
        identifier,
        extendableBackupFlag,
        iterationExponent,
        groupIndex,
        groupThreshold,
        groupCount,
      );
      throw new Error(
        `Wrong number of mnemonics. Expected ${String(threshold)} mnemonics starting with "${mnemonicFromIndices(prefix)}", \n but ${String(shares.size)} were provided.`,
      );
    }

    const recovered = await recoverSecret(threshold, shares);
    allShares.set(groupIndex, recovered);
  }

  const ems = await recoverSecret(groupThreshold, allShares);
  const id = intToIndices(BigInt(identifier), ITERATION_EXP_WORDS_LENGTH, 8);

  return crypt(
    ems,
    passphrase,
    iterationExponent,
    id,
    extendableBackupFlag,
    false,
  );
}

function decodeMnemonics(mnemonics: string[]): IDecodedMnemonics {
  const identifiers = new Set<number>();
  const extendableBackupFlags = new Set<number>();
  const iterationExponents = new Set<number>();
  const groupThresholds = new Set<number>();
  const groupCounts = new Set<number>();
  const groups = new Map<number, Map<number, Map<number, number[]>>>();

  mnemonics.forEach((mnemonic) => {
    const decoded = decodeMnemonic(mnemonic);

    identifiers.add(decoded.identifier);
    extendableBackupFlags.add(decoded.extendableBackupFlag);
    iterationExponents.add(decoded.iterationExponent);
    const groupIndex = decoded.groupIndex;
    groupThresholds.add(decoded.groupThreshold);
    groupCounts.add(decoded.groupCount);
    const memberIndex = decoded.memberIndex;
    const memberThreshold = decoded.memberThreshold;
    const share = decoded.share;

    const group = !groups.has(groupIndex)
      ? new Map<number, Map<number, number[]>>()
      : groups.get(groupIndex);
    if (!group) {
      throw new Error("Unable to initialize group map");
    }

    const member = !group.has(memberThreshold)
      ? new Map<number, number[]>()
      : group.get(memberThreshold);
    if (!member) {
      throw new Error("Unable to initalize member map");
    }
    member.set(memberIndex, share);
    group.set(memberThreshold, member);
    if (group.size !== 1) {
      throw new Error(
        "Invalid set of mnemonics. All mnemonics in a group must have the same member threshold.",
      );
    }
    groups.set(groupIndex, group);
  });

  if (
    identifiers.size !== 1 ||
    extendableBackupFlags.size !== 1 ||
    iterationExponents.size !== 1
  ) {
    throw new Error(
      `Invalid set of mnemonics. All mnemonics must begin with the same ${String(ITERATION_EXP_WORDS_LENGTH)} words.`,
    );
  }

  if (groupThresholds.size !== 1) {
    throw new Error(
      "Invalid set of mnemonics. All mnemonics must have the same group threshold.",
    );
  }

  if (groupCounts.size !== 1) {
    throw new Error(
      "Invalid set of mnemonics. All mnemonics must have the same group count.",
    );
  }

  return {
    identifier: identifiers.values().next().value,
    extendableBackupFlag: extendableBackupFlags.values().next().value,
    iterationExponent: iterationExponents.values().next().value,
    groupThreshold: groupThresholds.values().next().value,
    groupCount: groupCounts.values().next().value,
    groups,
  };
}

//
// Converts a share mnemonic to share data.
//
function decodeMnemonic(mnemonic: string): IDecodedMnemonic {
  const data = mnemonicToIndices(mnemonic);

  if (data.length < MNEMONICS_WORDS_LENGTH) {
    throw new Error(
      `Invalid mnemonic length. The length of each mnemonic must be at least ${String(MNEMONICS_WORDS_LENGTH)} words.`,
    );
  }

  const paddingLen = (RADIX_BITS * (data.length - METADATA_WORDS_LENGTH)) % 16;
  if (paddingLen > 8) {
    throw new Error("Invalid mnemonic length.");
  }

  const idExpExtInt = Number(
    intFromIndices(data.slice(0, ITERATION_EXP_WORDS_LENGTH)),
  );
  const identifier =
    idExpExtInt >>
    (ITERATION_EXP_BITS_LENGTH + EXTENDABLE_BACKUP_FLAG_BITS_LENGTH);
  const extendableBackupFlag =
    (idExpExtInt >> ITERATION_EXP_BITS_LENGTH) &
    ((1 << EXTENDABLE_BACKUP_FLAG_BITS_LENGTH) - 1);
  const iterationExponent =
    idExpExtInt & ((1 << ITERATION_EXP_BITS_LENGTH) - 1);

  if (!rs1024VerifyChecksum(data, extendableBackupFlag)) {
    throw new Error("Invalid mnemonic checksum");
  }

  const tmp = intFromIndices(
    data.slice(ITERATION_EXP_WORDS_LENGTH, ITERATION_EXP_WORDS_LENGTH + 2),
  );

  const indices = intToIndices(tmp, 5, 4);

  const groupIndex = indices[0];
  const groupThreshold = indices[1];
  const groupCount = indices[2];
  const memberIndex = indices[3];
  const memberThreshold = indices[4];

  const valueData = data.slice(
    ITERATION_EXP_WORDS_LENGTH + 2,
    data.length - CHECKSUM_WORDS_LENGTH,
  );

  if (groupCount < groupThreshold) {
    throw new Error(
      `Invalid mnemonic: ${mnemonic}.\n Group threshold (${String(groupThreshold)}) cannot be greater than group count (${String(groupCount)}).`,
    );
  }

  const valueInt = intFromIndices(valueData);

  try {
    const valueByteCount = bitsToBytes(
      RADIX_BITS * valueData.length - paddingLen,
    );
    const share = encodeBigInt(valueInt, valueByteCount);

    return {
      identifier: identifier,
      extendableBackupFlag: extendableBackupFlag,
      iterationExponent: iterationExponent,
      groupIndex: groupIndex,
      groupThreshold: groupThreshold + 1,
      groupCount: groupCount + 1,
      memberIndex: memberIndex,
      memberThreshold: memberThreshold + 1,
      share: share,
    };
  } catch (e) {
    throw new Error(`Invalid mnemonic padding (${String(e)})`);
  }
}

export function validateMnemonic(mnemonic: string): boolean {
  try {
    decodeMnemonic(mnemonic);
    return true;
  } catch {
    return false;
  }
}

function groupPrefix(
  identifier: number,
  extendableBackupFlag: number,
  iterationExponent: number,
  groupIndex: number,
  groupThreshold: number,
  groupCount: number,
): number[] {
  const idExpInt = BigInt(
    (identifier <<
      (ITERATION_EXP_BITS_LENGTH + EXTENDABLE_BACKUP_FLAG_BITS_LENGTH)) +
      (extendableBackupFlag << ITERATION_EXP_BITS_LENGTH) +
      iterationExponent,
  );

  const indc = intToIndices(idExpInt, ITERATION_EXP_WORDS_LENGTH, RADIX_BITS);

  const indc2 =
    (groupIndex << 6) + ((groupThreshold - 1) << 2) + ((groupCount - 1) >> 2);

  indc.push(indc2);
  return indc;
}

//
//  Converts share data to a share mnemonic.
//
export function encodeMnemonic(
  identifier: number[],
  extendableBackupFlag: number,
  iterationExponent: number,
  groupIndex: number,
  groupThreshold: number,
  groupCount: number,
  memberIndex: number,
  memberThreshold: number,
  value: number[],
): string {
  // Convert the share value from bytes to wordlist indices.
  const valueWordCount = bitsToWords(value.length * 8);

  const valueInt = decodeBigInt(value);
  const newIdentifier = Number(decodeBigInt(identifier));

  const gp = groupPrefix(
    newIdentifier,
    extendableBackupFlag,
    iterationExponent,
    groupIndex,
    groupThreshold,
    groupCount,
  );
  const tp = intToIndices(valueInt, valueWordCount, RADIX_BITS);

  const calc =
    (((groupCount - 1) & 3) << 8) + (memberIndex << 4) + (memberThreshold - 1);

  gp.push(calc);
  const shareData = gp.concat(tp);

  const checksum = rs1024CreateChecksum(shareData, extendableBackupFlag);

  return mnemonicFromIndices(shareData.concat(checksum));
}
