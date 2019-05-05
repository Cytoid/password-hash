import { randomBytes as randomCallback } from 'crypto'
import { promisify } from 'util'
import PasswordHasher, { RegisterHasher } from '.'
import { Scrypt, PBKDF2 } from './hashers'

const randomBytes = promisify(randomCallback)
function genRandomString() {
  return randomBytes(32)
    .then((buffer) => buffer.toString('base64'))
}

RegisterHasher(Scrypt, 0x00)
RegisterHasher(PBKDF2, 0x02)


describe('Password Hashing and Checks', () => {
  const pw = new PasswordHasher(PBKDF2)
  it('Hashes a password and passes it', async () => {
    expect.assertions(3)
    const password = await genRandomString()
    const buffer = await pw.hash(password)

    // The password was generated
    expect(buffer).toBeTruthy()

    // The password has the expected length
    expect(buffer.length).toBe(pw.passwordLength + pw.saltLength + pw.defaultHasher.optionLength + 5)

    // The generated password passes the checks
    expect(await pw.check(password, buffer)).toBeTruthy()
  })
  it('Does not pass faulty passwords', async () => {
    expect.assertions(1)
    const password1 =  await genRandomString()
    const password2 =  await genRandomString()
    const hash = await pw.hash(password1)

    // The generated password passes the checks
    expect(await pw.check(password2, hash)).not.toBeTruthy()
  })
})
