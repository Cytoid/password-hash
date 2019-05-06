import { compare, hash } from 'bcrypt'

import { ManagedHasher } from '../'

export default class BcryptHasher implements ManagedHasher {
  public static optionLength: number = 1
  public cost: number = 10

  constructor(options?: Buffer) {
    if (options) {
      this.cost = options.readUInt8(0)
    }
  }

  public hash(password: string): Promise<Buffer> {
    return hash(password, this.cost)
    .then((bcryptstr) => {
      const hashstr = bcryptstr.split('$')[3]
      return Buffer.from(hashstr.replace(/\./g, '+') + '+==', 'base64')
    })
  }

  public check(password: string, passwordHash: Buffer): Promise<boolean> {
    const paddedCost = this.cost < 10 ? '0' + this.cost : '' + this.cost
    const bcryptstr = '$2b$' + paddedCost + '$' + passwordHash.toString('base64').replace(/\+/g, '.').slice(0, -3)
    return compare(password, bcryptstr)
  }

  public getOptionBuffer(): Buffer {
    const buff = Buffer.alloc(BcryptHasher.optionLength)
    buff.writeUInt8(this.cost, 0)
    return buff
  }
}
