import { randomBytes as randomCallback } from 'crypto'
import { promisify } from 'util'
import PasswordHasher, {
  RegisterHasher,
  PasswordValidity,
} from '.'
import * as Hashers from './hashers'

const randomBytes = promisify(randomCallback)
function genRandomString() {
  return randomBytes(32)
    .then((buffer) => buffer.toString('base64'))
}

RegisterHasher(Hashers.Scrypt, 0x00)
RegisterHasher(Hashers.Bcrypt, 0x01)
RegisterHasher(Hashers.PBKDF2, 0x02)

describe("Scrypt", () => {
  const pw = new PasswordHasher(Hashers.Scrypt)
  it('Hashes a password and passes it', async () => {
    const password = await genRandomString()
    const buffer = await pw.hash(password)

    // The password was generated
    expect(buffer).toBeTruthy()

    // The generated password passes the checks
    expect(await pw.check(password, buffer)).toEqual(PasswordValidity.Valid)
  })
  it('Does not pass faulty passwords', async () => {
    const password1 = await genRandomString()
    const password2 = await genRandomString()
    const hash = await pw.hash(password1)

    // The generated password passes the checks
    expect(await pw.check(password2, hash)).toEqual(PasswordValidity.Invalid)
  })
  it('Tolerates Changes in hashing parameters', async () => {
    const oldHasher = new Hashers.Scrypt(pw.passwordLength)
    oldHasher.cost = 10
    const oldpw = new PasswordHasher(Hashers.Scrypt, oldHasher)
    const password = await genRandomString()
    const hash = await oldpw.hash(password)
    expect(await oldpw.check(password, hash)).toEqual(PasswordValidity.Valid)
    expect(await pw.check(password, hash)).toEqual(PasswordValidity.ValidOutdated)
  })
})

describe("Bcrypt", () => {
  const pw = new PasswordHasher(Hashers.Bcrypt)
  it('Hashes a password and passes it', async () => {
    const password = await genRandomString()
    const buffer = await pw.hash(password)

    // The password was generated
    expect(buffer).toBeTruthy()

    // The generated password passes the checks
    expect(await pw.check(password, buffer)).toEqual(PasswordValidity.Valid)
  })
  it('Does not pass faulty passwords', async () => {
    const password1 = await genRandomString()
    const password2 = await genRandomString()
    const hash = await pw.hash(password1)

    // The generated password passes the checks
    expect(await pw.check(password2, hash)).toEqual(PasswordValidity.Invalid)
  })
  it('Tolerates Changes in hashing parameters', async () => {
    const oldHasher = new Hashers.Bcrypt()
    oldHasher.cost = 8
    const oldpw = new PasswordHasher(Hashers.Bcrypt, oldHasher)
    const password = await genRandomString()
    const hash = await oldpw.hash(password)
    expect(await oldpw.check(password, hash)).toEqual(PasswordValidity.Valid)
    expect(await pw.check(password, hash)).toEqual(PasswordValidity.ValidOutdated)
  })
})

describe("PBKDF2", () => {
  const pw = new PasswordHasher(Hashers.PBKDF2)
  it('Hashes a password and passes it', async () => {
    const password = await genRandomString()
    const buffer = await pw.hash(password)

    // The password was generated
    expect(buffer).toBeTruthy()

    // The generated password passes the checks
    expect(await pw.check(password, buffer)).toEqual(PasswordValidity.Valid)
  })
  it('Does not pass faulty passwords', async () => {
    const password1 = await genRandomString()
    const password2 = await genRandomString()
    const hash = await pw.hash(password1)

    // The generated password passes the checks
    expect(await pw.check(password2, hash)).toEqual(PasswordValidity.Invalid)
  })
  it('Tolerates Changes in hashing parameters', async () => {
    const oldHasher = new Hashers.PBKDF2(pw.passwordLength)
    oldHasher.cost -= 3
    const oldpw = new PasswordHasher(Hashers.PBKDF2, oldHasher)
    const password = await genRandomString()
    const hash = await oldpw.hash(password)
    expect(await oldpw.check(password, hash)).toEqual(PasswordValidity.Valid)
    expect(await pw.check(password, hash)).toEqual(PasswordValidity.ValidOutdated)
  })
})

describe('Backward Compatibility', () => {
  it('Compatible with PHP password_hash', async () => {
    const pw = new PasswordHasher(Hashers.Scrypt)
    async function check(password: string, bcrypthash: string) {
      const params = bcrypthash.split('$')
      const hash = params[3]
      const cost = parseInt(params[2])
      const a = Buffer.concat([
        Uint8Array.of(0x01, cost),
        Buffer.from(hash.replace(/\./g, '+') + '+==', 'base64')
      ])
      expect(await pw.check(password, a)).toEqual(PasswordValidity.ValidOutdated)
    }
    await check('neoneoneo', '$2y$10$j6qgoJWmvdOgdok/kwP.4eiOiPCSEh/UEIojHJM5d3yIMK11wAL/G')
    await check('neoneoneo', '$2y$10$uMjwObGaWxNhJbv2k/1fVOsG.8vQPp45aw09TfvdUQAaf.8.64pmW')
    await check('neoneoneo', '$2y$10$VHTk99gZ0w0DKLn1mM2HEej6/dqN3b7fk5FguFSUj9cE/DvEnZJh6')
    await check('neoneoneo', '$2y$10$Lu3E5uiXyc0/ZMz0Zm.12OMpqzbpxDWfgsAk.WBdr8ksW2vsc5IlO')
  })
})