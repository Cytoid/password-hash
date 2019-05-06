import { compare, hash } from 'bcrypt'

import { ManagedHasher } from '../'

export default class BcryptHasher implements ManagedHasher {
	static optionLength: number = 1
	cost: number = 10

  constructor (options?: Buffer) {
		if (options) {
			this.cost = options.readUInt8(0)
		}
	}

  hash(password: string): Promise<Buffer> {
		return hash(password, this.cost)
		.then(bcryptstr => {
			const hashstr = bcryptstr.split('$')[3]
			return Buffer.from(hashstr.replace(/\./g, '+') + '+==', 'base64')
		})
	}
	
	check(password: string, hash: Buffer): Promise<boolean> {
		const paddedCost = this.cost < 10 ? '0' + this.cost : '' + this.cost
		const bcryptstr = '$2b$' + paddedCost + '$' + hash.toString('base64').replace(/\+/g, '.').slice(0, -3)
		return compare(password, bcryptstr)
	}

	getOptionBuffer(): Buffer {
		const buff = Buffer.alloc(BcryptHasher.optionLength)
		buff.writeUInt8(this.cost, 0)
		return buff
	}
}
