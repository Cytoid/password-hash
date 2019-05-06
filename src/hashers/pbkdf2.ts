import { BinaryLike, getHashes, pbkdf2 as pbkdf2Callback } from 'crypto'
import { promisify } from 'util'
import { Hasher } from '../'

const pbkdf2: (
	password: BinaryLike,
	salt: BinaryLike,
	iterations: number,
	keylen: number,
	digest: string,
) => Promise<Buffer> = promisify(pbkdf2Callback)

export enum PBKDF2Digest {
	SHA1,
	SHA256,
	SHA512,
}

const digestNames = [
	'sha1',
	'sha256',
	'sha512',
]

export default class PBKDF2Hasher implements Hasher {
	public static optionLength: number = 2

	public hashLength: number
	public cost: number = 15
	public digest = PBKDF2Digest.SHA512

	constructor(hashLength: number, options?: Buffer) {
		this.hashLength = hashLength
		if (options) {
			this.cost = options.readUInt8(0)
			this.digest = options.readUInt8(1)
		}
	}

	public hash(password: string, salt: Buffer): Promise<Buffer> {
		return pbkdf2(
			password,
			salt,
			Math.pow(2, this.cost),
			this.hashLength,
			digestNames[this.digest],
			)
	}
    public getOptionBuffer(): Buffer {
		const buff = Buffer.alloc(PBKDF2Hasher.optionLength)
		buff.writeUInt8(this.cost, 0)
		buff.writeUInt8(this.digest, 1)
		return buff
	}
}
