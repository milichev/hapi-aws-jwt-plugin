import axios from 'axios';
// @ts-ignore
import jwkToPem from 'jwk-to-pem';
import { JWK } from 'jwk-to-pem';

type PublicKey = JWK & {
  alg: string;
  e: string;
  kid: string;
  n: string;
  use: string;
};

interface PublicKeys {
  keys: PublicKey[];
}
export interface PublicKeyMeta {
  instance: PublicKey;
  pem: string;
}

export interface MapOfKidToPublicKey {
  [key: string]: PublicKeyMeta;
}
let cacheKeys: MapOfKidToPublicKey | undefined;

export const getPublicKeys = async (
  cognitoIssuer: string,
): Promise<MapOfKidToPublicKey> => {
  if (!cacheKeys) {
    const url = `${cognitoIssuer}/.well-known/jwks.json`;
    const publicKeys = await axios.get<PublicKeys>(url);

    cacheKeys = publicKeys.data.keys.reduce((agg, instance) => {
      const pem = jwkToPem(instance);
      agg[instance.kid] = {
        instance,
        pem,
      };
      return agg;
    }, {} as MapOfKidToPublicKey);

    // console.log(`Got public keys from ${cognitoIssuer}`, JSON.stringify(cacheKeys, null, 2));
  }

  return cacheKeys;
};
