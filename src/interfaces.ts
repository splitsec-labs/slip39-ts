export interface IDecodedMnemonics {
  extendableBackupFlag: number;
  groupCount: number;
  groupThreshold: number;
  groups: Map<number, Map<number, Map<number, number[]>>>;
  identifier: number;
  iterationExponent: number;
}

export interface IDecodedMnemonic {
  extendableBackupFlag: number;
  groupCount: number;
  groupIndex: number;
  groupThreshold: number;
  identifier: number;
  iterationExponent: number;
  memberIndex: number;
  memberThreshold: number;
  share: number[];
}

export interface ISlip39ConstructorOptions {
  extendableBackupFlag: number;
  identifier: number[];
  iterationExponent: number;
  groupCount: number;
  groupThreshold: number;
}
