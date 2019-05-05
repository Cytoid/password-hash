import { Buffer } from 'buffer'
import { randomBytes as randomCallback} from 'crypto'
import { promisify } from 'util'
import * as assert from 'assert'
const randomBytes = promisify(randomCallback)

export interface HasherConstructor {
  new (hashLength: number, options?: Buffer): Hasher
  id?: number
  optionLength: number
}

export interface Hasher {
  hash(password: string, salt: Buffer): Promise<Buffer>
  getOptionBuffer(): Buffer
}

export enum PasswordValidity {
  Invalid,
  Valid,
  ValidOutdated,
}

const RegisteredHashers: Map<number, HasherConstructor> = new Map()
export function RegisterHasher(hasher: HasherConstructor, id: number) {
  RegisteredHashers.set(id, hasher)
  hasher.id = id
}

class BufferReader {
  location: number = 0
  buffer: Buffer
  constructor (buffer: Buffer) {
    this.buffer = buffer
  }

  reset() {
    this.location = 0
  }

  read(length: number) {
    const start = this.location
    this.location += length
    return this.buffer.slice(start, this.location)
  }

  seek(location: number) {
    this.location = location
  }
}
/**
 * Binary format:
 * | UInt8: HasherID |
 * | UInt16: PasswordLength | UInt16: SaltLength |
 * | Hasher Defined Hashing Options |
 * | Password Hash |
 * | Salt |
 */
export default class PasswordHasher {
  defaultHasher: HasherConstructor

  private hasher: Hasher

  passwordLength: number = 128
  saltLength: number = 32

  constructor(hasher: HasherConstructor) {
    this.defaultHasher = hasher
    this.hasher = new hasher(this.passwordLength)
  }

  async hash(password: string): Promise<Buffer> {
	  const salt = await randomBytes(this.saltLength)
    const saltedPassword = await this.hasher.hash(password, salt)
    const buff = Buffer.alloc(5)

    assert.ok(Number.isInteger(this.defaultHasher.id), "The default hasher was never registered.")
    buff.writeUInt8(this.defaultHasher.id, 0)
    buff.writeUInt16LE(this.passwordLength, 1)
    buff.writeUInt16LE(this.saltLength, 3)
	  return Buffer.concat([
      buff,
      this.hasher.getOptionBuffer(),
      saltedPassword,
      salt
    ])
  }

  async check(password: string, hash: Buffer): Promise<PasswordValidity> {
    const hasherId = hash.readUInt8(0)
    const TheHasher = RegisteredHashers.get(hasherId)

    const passwordLength = hash.readUInt16LE(1)
    const saltLength = hash.readUInt16LE(3)

    const hashReader = new BufferReader(hash)
    hashReader.seek(5)

    const options = hashReader.read(TheHasher.optionLength)
    const passwordHash = hashReader.read(this.passwordLength)
    const salt = hashReader.read(this.saltLength)

    const hasher = new TheHasher(this.passwordLength, options)

    const trueHash = await hasher.hash(password, salt)

    if (!trueHash.equals(passwordHash)) {
      return PasswordValidity.Invalid
    }

    if (hasherId != this.defaultHasher.id ||
        passwordLength != this.passwordLength ||
        saltLength != this.saltLength ||
        !hasher.getOptionBuffer().equals(options)) {
      return PasswordValidity.ValidOutdated
    }
    return PasswordValidity.Valid
  }
}
