import { Buffer } from 'buffer'
import { randomBytes as randomCallback} from 'crypto'
import { promisify } from 'util'
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

export interface ManagedHasherConstructor {
  new (options?: Buffer): ManagedHasher
  id?: number
  optionLength: number
}
export interface ManagedHasher {
  hash(password: string): Promise<Buffer>
  getOptionBuffer(): Buffer
  check(password: string, hash: Buffer): Promise<boolean>
}

function isHasherManaged(hasher: Hasher | ManagedHasher): hasher is ManagedHasher {
  return (<ManagedHasher>hasher).check !== undefined;
}

function isHasherConstructorManaged(cons: HasherConstructor | ManagedHasherConstructor): cons is ManagedHasherConstructor {
  return cons.prototype.check !== undefined
}

export enum PasswordValidity {
  Invalid,
  Valid,
  ValidOutdated,
}

const RegisteredHashers: Map<number, HasherConstructor | ManagedHasherConstructor> = new Map()
export function RegisterHasher(hasher: HasherConstructor | ManagedHasherConstructor, id: number) {
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
  defaultHasher: HasherConstructor | ManagedHasherConstructor

  private hasher: Hasher | ManagedHasher

  passwordLength: number = 128
  saltLength: number = 32

  constructor(Hasher: HasherConstructor | ManagedHasherConstructor, hasher?: Hasher | ManagedHasher) {
    this.defaultHasher = Hasher
    if (hasher) {
      this.hasher = hasher
    } else if (isHasherConstructorManaged(Hasher)) {
      this.hasher = new Hasher()
    } else {
      this.hasher = new Hasher(this.passwordLength)
    }
  }

  async hash(password: string): Promise<Buffer> {
    if (isHasherManaged(this.hasher)) {
      const hash = await this.hasher.hash(password)
      return Buffer.concat([
        Uint8Array.of(this.defaultHasher.id),
        this.hasher.getOptionBuffer(),
        hash
      ])
    }
	  const salt = await randomBytes(this.saltLength)
    const saltedPassword = await this.hasher.hash(password, salt)
    const buff = Buffer.alloc(5)
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
    if (!RegisteredHashers.has(hasherId)) {
      throw new Error(`The Hasher ID ${hasherId} was never registered`)
    }
    const TheHasher = RegisteredHashers.get(hasherId)

    if (isHasherConstructorManaged(TheHasher)) {
      const options = hash.slice(1, 1 + TheHasher.optionLength)
      const hasher = new TheHasher(options)
      if (await hasher.check(password, hash.slice(1 + TheHasher.optionLength))) {
        if (hasherId == this.defaultHasher.id &&
            this.hasher.getOptionBuffer().equals(options)) {
          return PasswordValidity.Valid
        } else {
          return PasswordValidity.ValidOutdated
        }
      } else {
        return PasswordValidity.Invalid
      }
    }

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
        !this.hasher.getOptionBuffer().equals(options)) {
      return PasswordValidity.ValidOutdated
    }
    return PasswordValidity.Valid
  }
}

export * from './hashers'
