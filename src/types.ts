export interface AwsAuthImplementationOptions {
  userPoolId: string;
  region: string;
}

export interface Claim {
  sub: string;
  token_use: string;
  auth_time: number;
  iss: string;
  exp: number;
  username: string;
  client_id: string;
  [key: string]: unknown;
}
export interface TokenHeader {
  kid: string;
  alg: string;
}

export interface DecodedJwt {
  header: TokenHeader;
}
