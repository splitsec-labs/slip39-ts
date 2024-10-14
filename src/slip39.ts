import { MIN_ENTROPY_BITS } from "./constants";
import { ISlip39, ISlip39ConstructorOptions, ISlip39Node } from "./interfaces";
import {
  combineMnemonics,
  crypt,
  encodeMnemonic,
  generateIdentifier,
  splitSecret,
  validateMnemonic,
} from "./slip39_helper";
import { bitsToBytes, generateArray } from "./utils";

const MAX_DEPTH = 2;

/**
 * Slip39Node
 * For root node, description refers to the whole set's title e.g. "Hardware wallet X SSSS shares"
 * For children nodes, description refers to the group e.g. "Family group: mom, dad, sister, wife"
 */
class Slip39Node implements ISlip39Node {
  public mnemonic: string;
  public readonly index: number;
  public children: Slip39Node[];
  public description: string;

  constructor(
    index = 0,
    description = "",
    mnemonic = "",
    children: Slip39Node[] = [],
  ) {
    this.index = index;
    this.description = description;
    this.mnemonic = mnemonic;
    this.children = children;
  }

  get mnemonics(): string[] {
    if (this.children.length === 0) {
      return [this.mnemonic];
    }
    return this.children.reduce((prev: string[], item) => {
      return prev.concat(item.mnemonics);
    }, []);
  }
}

//
// Implementation of the SLIP-0039: Shamir's Secret-Sharing for Mnemonic Codes
// see: https://github.com/satoshilabs/slips/blob/master/slip-0039.md)
//
export class Slip39 implements ISlip39 {
  public readonly extendableBackupFlag: number;
  public readonly groupCount: number;
  public readonly groupThreshold: number;
  public readonly identifier: number[];
  public readonly iterationExponent: number;
  public root = new Slip39Node();

  constructor({
    iterationExponent = 0,
    extendableBackupFlag = 0,
    identifier,
    groupCount,
    groupThreshold,
  }: ISlip39ConstructorOptions) {
    this.iterationExponent = iterationExponent;
    this.extendableBackupFlag = extendableBackupFlag;

    if (identifier.length === 0) {
      throw new Error("Missing required parameter identifier");
    }
    this.identifier = identifier;

    if (!groupCount) {
      throw new Error("Missing required parameter groupCount");
    }
    this.groupCount = groupCount;

    if (!groupThreshold) {
      throw new Error("Missing required parameter groupThreshold");
    }
    this.groupThreshold = groupThreshold;
  }

  static async fromArray(
    masterSecret: number[],
    {
      extendableBackupFlag = 1,
      groups = [[1, 1, "Default 1-of-1 group share"]],
      iterationExponent = 0,
      identifier = generateIdentifier(),
      passphrase = "",
      groupThreshold = 1,
      title = "My default slip39 shares",
    } = {},
  ): Promise<Slip39> {
    if (masterSecret.length * 8 < MIN_ENTROPY_BITS) {
      throw Error(
        `The length of the master secret (${String(masterSecret.length)} bytes) must be at least ${String(bitsToBytes(MIN_ENTROPY_BITS))} bytes.`,
      );
    }

    if (masterSecret.length % 2 !== 0) {
      throw Error(
        "The length of the master secret in bytes must be an even number.",
      );
    }

    if (!/^[\x20-\x7E]*$/.test(passphrase)) {
      throw Error(
        "The passphrase must contain only printable ASCII characters (code points 32-126).",
      );
    }

    if (groupThreshold > groups.length) {
      throw Error(
        `The requested group threshold (${String(groupThreshold)}) must not exceed the number of groups (${String(groups.length)}).`,
      );
    }

    groups.forEach((item: any) => {
      if (item[0] === 1 && item[1] > 1) {
        throw Error(
          `Creating multiple member shares with member threshold 1 is not allowed. Use 1-of-1 member sharing instead. ${groups.join()}`,
        );
      }
    });

    const slip = new Slip39({
      iterationExponent: iterationExponent,
      extendableBackupFlag: extendableBackupFlag,
      identifier: identifier,
      groupCount: groups.length,
      groupThreshold: groupThreshold,
    });

    const encryptedMasterSecret = await crypt(
      masterSecret,
      passphrase,
      iterationExponent,
      slip.identifier,
      extendableBackupFlag,
    );

    slip.root = await slip.buildRecursive(
      new Slip39Node(0, title),
      groups,
      encryptedMasterSecret,
      groupThreshold,
    );
    return slip;
  }

  async buildRecursive(
    currentNode: Slip39Node,
    nodes: (number | string)[][],
    secret: number[],
    threshold: number,
    index?: number,
  ): Promise<Slip39Node> {
    // It means it's a leaf.
    if (nodes.length === 0) {
      currentNode.mnemonic = encodeMnemonic(
        this.identifier,
        this.extendableBackupFlag,
        this.iterationExponent,
        index || 0,
        this.groupThreshold,
        this.groupCount,
        currentNode.index,
        threshold,
        secret,
      );
      return currentNode;
    }

    const secretShares = await splitSecret(threshold, nodes.length, secret);
    let children: Slip39Node[] = [];
    let idx = 0;

    for (const item of nodes) {
      if (
        item.length < 2 ||
        typeof item[0] !== "number" ||
        typeof item[1] !== "number"
      ) {
        throw new Error("Group array must contain two numbers");
      }

      // n=threshold
      const n = item[0];
      // m=members
      const m = item[1];
      // d=description
      const d: string =
        item.length > 2 && typeof item[2] === "string" ? item[2] : "";

      // Generate leaf members, means their `m` is `0`
      const members = generateArray([], m, () => [n, 0, d]) as number[][];

      const node = new Slip39Node(idx, d);
      const branch = await this.buildRecursive(
        node,
        members,
        secretShares[idx],
        n,
        currentNode.index,
      );

      children = children.concat(branch);
      idx = idx + 1;
    }
    currentNode.children = children;
    return currentNode;
  }

  static async recoverSecret(
    mnemonics: string[],
    passphrase = "",
  ): Promise<number[]> {
    return combineMnemonics(mnemonics, passphrase);
  }

  static validateMnemonic(mnemonic: string): boolean {
    return validateMnemonic(mnemonic);
  }

  fromPath(path: string): Slip39Node {
    this.validatePath(path);

    const children = this.parseChildren(path);

    if (typeof children === "undefined" || children.length === 0) {
      return this.root;
    }

    return children.reduce((prev, childNumber) => {
      const childrenLen = prev.children.length;
      if (childNumber >= childrenLen) {
        throw new Error(
          `The path index (${String(childNumber)}) exceeds the children index (${String(childrenLen - 1)}).`,
        );
      }

      return prev.children[childNumber];
    }, this.root);
  }

  validatePath(path: string): void {
    if (!path.match(/(^r)(\/\d{1,2}){0,2}$/)) {
      throw new Error('Expected valid path e.g. "r/0/0".');
    }

    const depth = path.split("/");
    const pathLength = depth.length - 1;
    if (pathLength > MAX_DEPTH) {
      throw new Error(
        `Path's (${path}) max depth (${String(MAX_DEPTH)}) is exceeded (${String(pathLength)}).`,
      );
    }
  }

  parseChildren(path: string): number[] {
    const splitted = path.split("/").slice(1);

    return splitted.map((pathFragment) => {
      return parseInt(pathFragment);
    });
  }
}
