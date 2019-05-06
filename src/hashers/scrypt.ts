import { BinaryLike, scrypt as scryptCallback, ScryptOptions } from 'crypto'
import { promisify } from 'util'
import { Hasher } from '../'

const scrypt: (
  password: BinaryLike,
  salt: BinaryLike,
  keylen: number,
  options: ScryptOptions,
) => Promise<Buffer> = promisify(scryptCallback)

export default class ScryptHasher implements Hasher {
  public static optionLength: number = 3

  public hashLength: number
  public cost: number = 14
  public blockSize: number = 8
  public parallelization: number = 1

  constructor(hashLength: number, options?: Buffer) {
    this.hashLength = hashLength
    if (options) {
      this.cost = options.readUInt8(0)
      this.blockSize = options.readUInt8(1)
      this.parallelization = options.readUInt8(2)
    }
  }

  public hash(password: string, salt: Buffer): Promise<Buffer> {
    return scrypt(password, salt, this.hashLength, {
      N: Math.pow(2, this.cost),
      r: this.blockSize,
      p: this.parallelization,
    })
  }
    public getOptionBuffer(): Buffer {
    const buff = Buffer.alloc(ScryptHasher.optionLength)
    buff.writeUInt8(this.cost, 0)
    buff.writeUInt8(this.blockSize, 1)
    buff.writeUInt8(this.parallelization, 2)
    return buff
  }
}
