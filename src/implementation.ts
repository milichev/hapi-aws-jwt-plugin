import * as Boom from '@hapi/boom';
import { AuthenticationData, ServerAuthScheme } from '@hapi/hapi';
import * as Hoek from '@hapi/hoek';
import { promisify } from 'es6-promisify';
import * as jsonwebtoken from 'jsonwebtoken';
import { decodeJwt } from './decodeJwt';
import { getPublicKeys, PublicKeyMeta } from './getPublicKeys';
import { getRawToken } from './getRawToken';
import { SCHEME_NAME } from './plugin';
import { AwsAuthImplementationOptions, Claim } from './types';

type TokenPayload = {};

const verifyPromised: (
  token: string,
  secretOrPublicKey: jsonwebtoken.Secret | jsonwebtoken.GetPublicKeyOrSecret,
) => Promise<TokenPayload> = promisify(jsonwebtoken.verify);

export const implementation = ((
  server,
  options?: AwsAuthImplementationOptions,
) => {
  Hoek.assert(options, 'AWS JWT authentication options missing');

  const unauthorized = (message: string | null = null) =>
    Boom.unauthorized(message, SCHEME_NAME);

  return {
    async authenticate(req, h) {
      const result: AuthenticationData = { credentials: {} };

      const rawToken = getRawToken(req);
      if (!rawToken) {
        return h.unauthenticated(unauthorized('Missing authentication'));
      }

      const decoded = decodeJwt(rawToken);
      if (!decoded) {
        return h.unauthenticated(unauthorized('Invalid Authentication'));
      }

      const { region, userPoolId } = options!;
      const cognitoIssuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;
      const keys = await getPublicKeys(cognitoIssuer);

      const key: PublicKeyMeta = keys[decoded.header.kid];
      if (!key) {
        return h.unauthenticated(unauthorized('claim made for unknown kid'));
      }

      let claim: Claim;

      try {
        claim = (await verifyPromised(rawToken, key.pem)) as Claim;
      } catch (err) {
        if (err.name === 'TokenExpiredError') {
          return h.unauthenticated(unauthorized('auth expired'));
        }
        // TODO: remove the console OR replace with CloudWatch logging once all the error cases are defined.
        // console.error('JWT verify error', err);
        return h.unauthenticated(unauthorized('invalid claim'));
      }

      const { exp, auth_time, iss, token_use } = claim;

      const currentSeconds = Math.round(new Date().valueOf() / 1000);
      if (currentSeconds > exp) {
        return h.unauthenticated(unauthorized('claim is expired'));
      }

      // when the request is done right after the token is issued, the auth_time
      // might be up to a few seconds ahead of the current time.
      const maxTimeDriftSeconds = 2;
      if (auth_time - currentSeconds > maxTimeDriftSeconds) {
        return h.unauthenticated(unauthorized('claim auth time is invalid'));
      }

      if (iss !== cognitoIssuer) {
        return h.unauthenticated(unauthorized('claim issuer is invalid'));
      }

      if (token_use !== 'access') {
        return h.unauthenticated(unauthorized('claim use is not access'));
      }

      result.credentials = claim;

      return h.authenticated(result);
    },
  };
}) as ServerAuthScheme;
