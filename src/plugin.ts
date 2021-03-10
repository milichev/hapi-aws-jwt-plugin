import { Plugin } from '@hapi/hapi';
import { implementation } from './implementation';
import { onPreStart } from './onPreStart';

export const SCHEME_NAME = 'awsjwt';

export interface AwsJwtPluginOptions {}

export const awsJwtPlugin: Plugin<AwsJwtPluginOptions> = {
  pkg: require('../package.json'),

  async register(server, options) {
    server.ext('onPreStart', onPreStart);
    server.auth.scheme(SCHEME_NAME, implementation);
  },
};
