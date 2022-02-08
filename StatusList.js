/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import Bitstring from '@digitalbazaar/bitstring';

export class StatusList {
  constructor({length, buffer} = {}) {
    this.bitstring = new Bitstring({length, buffer});
    this.length = this.bitstring.length;
  }

  setStatus(index, revoked) {
    if(typeof revoked !== 'boolean') {
      throw new TypeError('"revoked" must be a boolean.');
    }
    return this.bitstring.set(index, revoked);
  }

  getStatus(index) {
    return this.bitstring.get(index);
  }

  async encode() {
    return this.bitstring.encodeBits();
  }

  static async decode({encodedList}) {
    const buffer = await Bitstring.decodeBits({encoded: encodedList});
    return new StatusList({buffer});
  }
}
