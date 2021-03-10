import { Request } from '@hapi/hapi';

export function getRawToken(req: Request): string | null {
  const authHeader = req.headers['authorization'];
  const bearerPrefix = 'Bearer ';

  return authHeader && authHeader.startsWith(bearerPrefix)
    ? authHeader.slice(bearerPrefix.length)
    : null;
}
