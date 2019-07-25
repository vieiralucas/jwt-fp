import { Either, left, mapLeft } from 'fp-ts/lib/Either'
import * as t from 'io-ts'
import { PathReporter } from 'io-ts/lib/PathReporter'
import * as jwt from 'jsonwebtoken'

export type Algorithm = 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'RS384' | 'RS512' | 'ES256' | 'ES384' | 'ES512' | 'none'

export interface ISignOptions extends jwt.SignOptions {
  algorithm: Algorithm
}

const SignPayload = t.intersection([
  t.partial({
    exp: t.number,
    iat: t.number,
    nbf: t.number,
  }),
  t.interface({
    data: t.object,
  }),
])

export interface ISignPayload extends t.TypeOf<typeof SignPayload> {}

export interface IVerifyOptions extends jwt.VerifyOptions {
  algorithm: Algorithm
}

const VerifyPayload = t.intersection([
  t.partial({
    exp: t.number,
    nbf: t.number,
  }),
  t.interface({
    data: t.object,
    iat: t.number,
  }),
])
export interface IVerifyPayload extends t.TypeOf<typeof VerifyPayload> {}

export { TokenExpiredError, JsonWebTokenError, NotBeforeError } from 'jsonwebtoken'
export type VerifyError = jwt.TokenExpiredError | jwt.JsonWebTokenError | jwt.NotBeforeError

/**
 * Sign the given payload into a JSON Web Token string
 * @param {SignPayload} payload - Payload to sign, could be an literal, buffer or string
 * @param {String|Buffer} secretOrPrivateKey - Either the secret for HMAC algorithms, or the PEM encoded private key for RSA and ECDSA.
 * @param {ISignOptions} [options] - Options for the signature
 * @returns {String} The JSON Web Token string
 */
export const sign = (payload: ISignPayload, secretOrPrivateKey: string | Buffer, options?: ISignOptions): string =>
  jwt.sign(payload, secretOrPrivateKey, options)

/**
 * Verify given token using a secret or a public key to get a decoded token
 * @param {String} token - JWT string to verify
 * @param {String|Buffer} secretOrPublicKey - Either the secret for HMAC algorithms, or the PEM encoded public key for RSA and ECDSA.
 * @param {VerifyOptions} [options] - Options for the verification
 * @returns {Either<VerifyError, string>} Either an error or the decoded string.
 */
export const verify = (
  token: string,
  secretOrPublicKey: string | Buffer,
  options?: IVerifyOptions,
): Either<VerifyError, IVerifyPayload> => {
  try {
    const decodedToken = jwt.verify(token, secretOrPublicKey, options)
    const decodedPayload = VerifyPayload.decode(decodedToken)

    return mapLeft(() => new jwt.JsonWebTokenError(PathReporter.report(decodedPayload).join(', ')))(decodedPayload)
  } catch (err) {
    if (isVerifyError(err)) {
      return left(err)
    }

    return left(new jwt.JsonWebTokenError(err.message, err))
  }
}

/**
 * Returns `true` if err is a `VerifyError`, `false` otherwise
 * @param {Error} err
 * @returns {Boolean} Whether err is a `VerifyError` or not
 */
export const isVerifyError = (err: Error): err is VerifyError =>
  err instanceof jwt.TokenExpiredError || err instanceof jwt.JsonWebTokenError || err instanceof jwt.NotBeforeError
