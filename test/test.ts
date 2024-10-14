import { Slip39 } from "../src";
import { decodeHexString, encodeHexString } from "../src";
// @ts-ignore
import { getCombinations, shuffle } from "./test_utils";

const MASTERSECRET = "ABCDEFGHIJKLMNOP";
const MASTERSECRET_HEX = encodeHexString(MASTERSECRET);
const PASSPHRASE = "TREZOR";
const ONE_GROUP = [[5, 7]];

let slip15: Slip39;
let slip15NoPW: Slip39;

beforeAll(async () => {
  slip15 = await Slip39.fromArray(MASTERSECRET_HEX, {
    passphrase: PASSPHRASE,
    groupThreshold: 1,
    groups: ONE_GROUP,
  });

  slip15NoPW = await Slip39.fromArray(MASTERSECRET_HEX, {
    groupThreshold: 1,
    groups: ONE_GROUP,
  });
});

describe("Basic Tests", () => {
  it("Should successfully setup a Slip39 object fromArray()", async () => {
    expect(slip15).toBeDefined();
  });

  it("Should successfully setup a Slip39 object fromPath()", async () => {
    let mnemonics = slip15.fromPath("r/0").mnemonics;

    expect(mnemonics).toBeDefined();
  });

  describe("Test threshold 1 with 5 of 7 shares of a group combinations", () => {
    let combinations = getCombinations([0, 1, 2, 3, 4, 5, 6], 5);
    combinations.forEach((item) => {
      shuffle(item);
      let description = `Test shuffled combination ${item.join(" ")}.`;
      it(description, async () => {
        let mnemonics = slip15.fromPath("r/0").mnemonics;

        let shares = item.map((idx) => mnemonics[idx]);
        expect(decodeHexString(MASTERSECRET_HEX)).toBe(
          decodeHexString(await Slip39.recoverSecret(shares, PASSPHRASE)),
        );
      });
    });
  });

  describe("Test passphrase", () => {
    it("should return valid mastersecret when user submits valid passphrase", async () => {
      let mnemonics = slip15.fromPath("r/0").mnemonics;
      expect(decodeHexString(MASTERSECRET_HEX)).toBe(
        decodeHexString(
          await Slip39.recoverSecret(mnemonics.slice(0, 5), PASSPHRASE),
        ),
      );
    });
    it("should NOT return valid mastersecret when user submits invalid passphrase", async () => {
      let mnemonics = slip15.fromPath("r/0").mnemonics;

      expect(decodeHexString(MASTERSECRET_HEX)).not.toBe(
        decodeHexString(await Slip39.recoverSecret(mnemonics.slice(0, 5))),
      );
    });
    it("should return valid mastersecret when user does not submit passphrase", async () => {
      let nopwMnemonics = slip15NoPW.fromPath("r/0").mnemonics;
      expect(decodeHexString(MASTERSECRET_HEX)).toBe(
        decodeHexString(await Slip39.recoverSecret(nopwMnemonics.slice(0, 5))),
      );
    });
  });

  describe("Test iteration exponent", () => {
    it("should return valid mastersecret when user apply valid iteration exponent", async () => {
      const slip1 = await Slip39.fromArray(MASTERSECRET_HEX, {
        iterationExponent: 1,
      });
      expect(decodeHexString(MASTERSECRET_HEX)).toBe(
        decodeHexString(
          await Slip39.recoverSecret(slip1.fromPath("r/0").mnemonics),
        ),
      );

      const slip2 = await Slip39.fromArray(MASTERSECRET_HEX, {
        iterationExponent: 2,
      });
      expect(decodeHexString(MASTERSECRET_HEX)).toBe(
        decodeHexString(
          await Slip39.recoverSecret(slip2.fromPath("r/0").mnemonics),
        ),
      );
    });
    /**
     * assert.throws(() => x.y.z);
     * assert.throws(() => x.y.z, ReferenceError);
     * assert.throws(() => x.y.z, ReferenceError, /is not defined/);
     * assert.throws(() => x.y.z, /is not defined/);
     * assert.doesNotThrow(() => 42);
     * assert.throws(() => x.y.z, Error);
     * assert.throws(() => model.get.z, /Property does not exist in model schema./)
     * Ref: https://stackoverflow.com/questions/21587122/mocha-chai-expect-to-throw-not-catching-thrown-errors
     */
    it("should throw an Error when user submits invalid iteration exponent", async () => {
      await expect(async () => {
        await Slip39.fromArray(MASTERSECRET_HEX, {
          iterationExponent: -1,
        });
      }).rejects.toThrow(
        "Invalid iteration exponent (-1). Expected between 0 and 16",
      );
      await expect(async () => {
        await Slip39.fromArray(MASTERSECRET_HEX, {
          iterationExponent: 33,
        });
      }).rejects.toThrow(
        "Invalid iteration exponent (33). Expected between 0 and 16",
      );
    });
  });
});

// FIXME: finish it.
describe("Group Sharing Tests", () => {
  describe("Test all valid combinations of mnemonics", () => {
    const groups = [
      [3, 5, "Group 0"],
      [3, 3, "Group 1"],
      [2, 5, "Group 2"],
      [1, 1, "Group 3"],
    ];

    let slip: Slip39;
    let group2Mnemonics: string[];
    let group3Mnemonic: string;

    beforeAll(async () => {
      slip = await Slip39.fromArray(MASTERSECRET_HEX, {
        groupThreshold: 2,
        groups: groups,
        title: "Trezor one SSSS",
      });
      group2Mnemonics = slip.fromPath("r/2").mnemonics;
      group3Mnemonic = slip.fromPath("r/3").mnemonics[0];
    });

    it("Should include overall split title", () => {
      expect(slip.fromPath("r").description).toBe("Trezor one SSSS");
    });
    it("Should include group descriptions", () => {
      expect(slip.fromPath("r/0").description).toBe("Group 0");
      expect(slip.fromPath("r/1").description).toBe("Group 1");
      expect(slip.fromPath("r/2").description).toBe("Group 2");
      expect(slip.fromPath("r/3").description).toBe("Group 3");
    });
    it("Should return the valid master secret when it tested with minimal sets of mnemonics.", async () => {
      const mnemonics = group2Mnemonics
        .filter((_, index) => {
          return index === 0 || index === 2;
        })
        .concat(group3Mnemonic);

      expect(decodeHexString(MASTERSECRET_HEX)).toBe(
        decodeHexString(await Slip39.recoverSecret(mnemonics)),
      );
    });
    it("TODO: Should NOT return the valid master secret when one complete group and one incomplete group out of two groups required", () => {
      expect(true).toBeTruthy();
    });
    it("TODO: Should return the valid master secret when one group of two required but only one applied.", () => {
      expect(true).toBeTruthy();
    });
  });
});

// The test vectors are given as a list of quadruples. The first element of the quadruple is a description of the
// test vector, the second is a list of mnemonics, the third is the master secret which results from combining the
// mnemonics, and the fourth is the BIP32 master extended private key derived from the master secret. The master
// secret is encoded as a string containing two hexadecimal digits for each byte. If the string is empty, then
// attempting to combine the given set of mnemonics should result in an error. The passphrase "TREZOR" is used for
// all valid sets of mnemonics.
//  https://github.com/trezor/python-shamir-mnemonic/blob/master/vectors.json
describe("Original test vectors Tests", () => {
  let fs = require("fs");
  let path = require("path");
  let filePath = path.join(__dirname, "vectors.json");

  let content = fs.readFileSync(filePath, "utf8");

  const tests = JSON.parse(content);
  // TODO: implement interface for the vector types
  tests.forEach((item: any) => {
    let description = item[0];
    let mnemonics = item[1];
    let masterSecret = Buffer.from(item[2], "hex");

    it(description, async () => {
      if (masterSecret.length !== 0) {
        let ms = await Slip39.recoverSecret(mnemonics, PASSPHRASE);
        expect(masterSecret.every((v, i) => v === ms[i])).toBeTruthy();
      } else {
        await expect(
          async () => await Slip39.recoverSecret(mnemonics, PASSPHRASE),
        ).rejects.toThrow();
      }
    });
  });
});

describe("Invalid Shares", () => {
  const tests = [
    [
      "Short master secret",
      1,
      [[2, 3]],
      MASTERSECRET_HEX.slice(0, 14),
      "The length of the master secret (14 bytes) must be at least 16 bytes.",
    ],
    [
      "Odd length master secret",
      1,
      [[2, 3]],
      MASTERSECRET_HEX.concat([55]),
      "The length of the master secret in bytes must be an even number.",
    ],
    [
      "Group threshold exceeds number of groups",
      3,
      [
        [3, 5],
        [2, 5],
      ],
      MASTERSECRET_HEX,
      "The requested group threshold (3) must not exceed the number of groups (2).",
    ],
    [
      "Invalid group threshold.",
      0,
      [
        [3, 5],
        [2, 5],
      ],
      MASTERSECRET_HEX,
      "Missing required parameter groupThreshold",
    ],
    [
      "Member threshold exceeds number of members",
      2,
      [
        [3, 2],
        [2, 5],
      ],
      MASTERSECRET_HEX,
      "The requested threshold (3) must not exceed the number of shares (2).",
    ],
    [
      "Invalid member threshold",
      2,
      [
        [0, 2],
        [2, 5],
      ],
      MASTERSECRET_HEX,
      "The requested threshold (0) must be a positive integer.",
    ],
    [
      "Group with multiple members and threshold 1",
      2,
      [
        [3, 5],
        [1, 3],
        [2, 5],
      ],
      MASTERSECRET_HEX,
      "Creating multiple member shares with member threshold 1 is not allowed. Use 1-of-1 member sharing instead. 3,5,1,3,2,5",
    ],
  ];

  // TODO: Implement interface for this test
  tests.forEach((item: any) => {
    let description = item[0];
    let threshold = item[1];

    let groups = item[2];
    let secret = item[3];
    let errorMsg = item[4];

    it(description, async () => {
      await expect(
        async () =>
          await Slip39.fromArray(secret, {
            groupThreshold: threshold,
            groups: groups,
          }),
      ).rejects.toThrow(errorMsg);
    });
  });
});

describe("Mnemonic Validation", () => {
  describe("Valid Mnemonics", () => {
    it(`Mnemonics should be valid`, () => {
      let mnemonics = slip15.fromPath("r/0").mnemonics;
      mnemonics.forEach((mnemonic, _) => {
        const isValid = Slip39.validateMnemonic(mnemonic);
        expect(isValid).toBeTruthy();
      });
    });
  });

  const vectors: {
    description: string;
    mnemonics: string[];
  }[] = [
    {
      description: "2. Mnemonic with invalid checksum (128 bits)",
      mnemonics: [
        "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision kidney",
      ],
    },
    {
      description: "21. Mnemonic with invalid checksum (256 bits)",
      mnemonics: [
        "theory painting academic academic armed sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips brave detect lunar",
      ],
    },
    {
      description: "3. Mnemonic with invalid padding (128 bits)",
      mnemonics: [
        "duckling enlarge academic academic email result length solution fridge kidney coal piece deal husband erode duke ajar music cargo fitness",
      ],
    },
    {
      description: "22. Mnemonic with invalid padding (256 bits)",
      mnemonics: [
        "theory painting academic academic campus sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips facility obtain sister",
      ],
    },
    {
      description:
        "10. Mnemonics with greater group threshold than group counts (128 bits)",
      mnemonics: [
        "music husband acrobat acid artist finance center either graduate swimming object bike medical clothes station aspect spider maiden bulb welcome",
        "music husband acrobat agency advance hunting bike corner density careful material civil evil tactics remind hawk discuss hobo voice rainbow",
        "music husband beard academic black tricycle clock mayor estimate level photo episode exclude ecology papa source amazing salt verify divorce",
      ],
    },
    {
      description:
        "29. Mnemonics with greater group threshold than group counts (256 bits)",
      mnemonics: [
        "smirk pink acrobat acid auction wireless impulse spine sprinkle fortune clogs elbow guest hush loyalty crush dictate tracks airport talent",
        "smirk pink acrobat agency dwarf emperor ajar organize legs slice harvest plastic dynamic style mobile float bulb health coding credit",
        "smirk pink beard academic alto strategy carve shame language rapids ruin smart location spray training acquire eraser endorse submit peaceful",
      ],
    },
    {
      description: "39. Mnemonic with insufficient length",
      mnemonics: [
        "junk necklace academic academic acne isolate join hesitate lunar roster dough calcium chemical ladybug amount mobile glasses verify cylinder",
      ],
    },
    {
      description: "40. Mnemonic with invalid master secret length",
      mnemonics: [
        "fraction necklace academic academic award teammate mouse regular testify coding building member verdict purchase blind camera duration email prepare spirit quarter",
      ],
    },
  ];

  vectors.forEach((item) => {
    describe(item.description, () => {
      item.mnemonics.forEach((mnemonic, index) => {
        it(`Mnemonic at index ${index} should be invalid`, () => {
          const isValid = Slip39.validateMnemonic(mnemonic);

          expect(isValid).toBeFalsy();
        });
      });
    });
  });
});

function itTestArray(t: number, g: number, gs: any[], e: number): void {
  it(`recover master secret for ${t} shares (threshold=${t}) of ${g} '[1, 1,]' groups with extendable backup flag set to ${e}",`, async () => {
    let slip = await Slip39.fromArray(MASTERSECRET_HEX, {
      groups: gs.slice(0, g),
      passphrase: PASSPHRASE,
      groupThreshold: t,
      extendableBackupFlag: e,
    });

    let mnemonics = slip.fromPath("r").mnemonics.slice(0, t);

    let recoveredSecret = await Slip39.recoverSecret(mnemonics, PASSPHRASE);

    expect(MASTERSECRET).toBe(String.fromCharCode(...recoveredSecret));
  });
}

describe("Groups test (T=1, N=1 e.g. [1,1]) - ", () => {
  let totalGroups = 16;
  let groups = Array.from(Array(totalGroups), () => [1, 1]);

  for (
    let extendableBackupFlag = 0;
    extendableBackupFlag <= 1;
    extendableBackupFlag++
  ) {
    for (let group = 1; group <= totalGroups; group++) {
      for (let threshold = 1; threshold <= group; threshold++) {
        itTestArray(threshold, group, groups, extendableBackupFlag);
      }
    }
  }
});
