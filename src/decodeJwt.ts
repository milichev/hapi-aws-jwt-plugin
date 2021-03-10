import { DecodedJwt, TokenHeader } from './types';

export function decodeJwt(rawJwt: string): DecodedJwt | null {
  const tokenSections = (rawJwt || '').split('.');
  if (tokenSections.length !== 3) {
    throw new Error('requested token is invalid');
  }

  const headerJSON = Buffer.from(tokenSections[0], 'base64').toString('utf8');
  const header = JSON.parse(headerJSON) as TokenHeader;

  return { header };
}
