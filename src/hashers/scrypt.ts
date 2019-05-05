import { HasherConstructor, Hasher } from '../'
import { scrypt as scryptCallback, ScryptOptions, BinaryLike } from 'crypto'
import { promisify } from 'util'

const scrypt: (
	password: BinaryLike,
	salt: BinaryLike,
	keylen: number,
	options: ScryptOptions
) => Promise<Buffer> = promisify(scryptCallback)

class ScryptHasher implements Hasher {
	static optionLength: number = 3

	hashLength: number
	cost: number = 14
	blockSize: number = 8
	parallelization: number = 1

	constructor (hashLength: number, options?: Buffer) {
		this.hashLength = hashLength
		if (options) {
			this.cost = options.readUInt8(0)
			this.blockSize = options.readUInt8(1)
			this.parallelization = options.readUInt8(2)
		}
	}

	hash(password: string, salt: Buffer): Promise<Buffer> {
		return scrypt(password, salt, this.hashLength, {
			N: Math.pow(2, this.cost),
			r: this.blockSize,
			p: this.parallelization,
		})
	}
    getOptionBuffer(): Buffer {
		const buff = Buffer.alloc(ScryptHasher.optionLength)
		buff.writeUInt8(this.cost, 0)
		buff.writeUInt8(this.blockSize, 1)
		buff.writeUInt8(this.parallelization, 2)
		return buff
	}
}

const TheHasher: HasherConstructor = ScryptHasher
export default TheHasher
