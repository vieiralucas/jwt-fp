import { isVerifyError, JsonWebTokenError, NotBeforeError, sign, TokenExpiredError, verify } from '../'

test('sign and verify', () => {
  const payload = { foo: 'bar' }
  const secret = 'shh'

  const token = sign({ iat: 1, exp: Date.now() + 11000, nbf: 1, data: payload }, secret)
  const decoded = verify(token, secret)

  if (decoded.isLeft()) {
    expect(decoded.isLeft()).toBeFalsy()
    return
  }

  expect(decoded.value.data).toEqual(payload)
})

test('sign and verify with invalid secret should give a left(JsonWebTokenError)', () => {
  const payload = { foo: 'bar' }
  const secret = 'shh'

  const token = sign({ data: payload }, secret)
  const decoded = verify(token, secret + 'nops')

  if (decoded.isRight()) {
    expect(decoded.isRight()).toBeFalsy()
    return
  }

  expect(decoded.value).toBeInstanceOf(JsonWebTokenError)
})

test('sign and verify with expired token should give a left(TokenExpiredError)', () => {
  const payload = { foo: 'bar' }
  const secret = 'shh'

  const token = sign({ exp: 1, data: payload }, secret)
  const decoded = verify(token, secret)

  if (decoded.isRight()) {
    expect(decoded.isRight()).toBeFalsy()
    return
  }

  expect(decoded.value).toBeInstanceOf(TokenExpiredError)
})

test('sign and verify before nbf gives a left(NotBeforeError)', () => {
  const payload = { foo: 'bar' }
  const secret = 'shh'

  const token = sign({ nbf: Date.now() + 10000, data: payload }, secret)
  const decoded = verify(token, secret)

  if (decoded.isRight()) {
    expect(decoded.isRight()).toBeFalsy()
    return
  }

  expect(decoded.value).toBeInstanceOf(NotBeforeError)
})

test('isVerifyError returns true when getting a JsonWebTokenError', () => {
  expect(isVerifyError(new JsonWebTokenError('JsonWebTokenError'))).toBeTruthy()
})

test('isVerifyError returns true when getting a NotBeforeError', () => {
  expect(isVerifyError(new NotBeforeError('NotBeforeError', new Date()))).toBeTruthy()
})

test('isVerifyError returns true when getting a TokenExpiredError', () => {
  expect(isVerifyError(new TokenExpiredError('TokenExpiredError', new Date(1)))).toBeTruthy()
})

test('isVerifyError returns false when getting another type of Error', () => {
  expect(isVerifyError(new Error('not a verify error'))).toBeFalsy()
})
