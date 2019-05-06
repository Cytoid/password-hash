import { compare, hash } from 'bcrypt'

import { ManagedHasher, ManagedHasherConstructor } from '../'

class BcryptHasher implements ManagedHasher {
	static optionLength: number = 1
	cost: number = 10
    hash(password: string): Promise<Buffer> {
		return hash(password, this.cost)
		.then(bcryptstr => {
			const hashstr = bcryptstr.split('$')[3]
			return Buffer.from(hashstr.replace(/\./g, '+') + '+==', 'base64')
		})
	}
	
	check(password: string, hash: Buffer): Promise<boolean> {
		const bcryptstr = '$2b$' + this.cost + '$' + hash.toString('base64').replace(/\+/g, '.').slice(0, -3)
		return compare(password, bcryptstr)
	}

	getOptionBuffer(): Buffer {
		const buff = Buffer.alloc(BcryptHasher.optionLength)
		buff.writeUInt8(this.cost, 0)
		return buff
	}
}

const TheHasher: ManagedHasherConstructor = BcryptHasher
export default TheHasher
