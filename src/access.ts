import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from 'jose';

export interface AccessConfig {
  /** Zero Trust team domain, e.g. "myteam.cloudflareaccess.com". */
  teamDomain: string;
  /** Application Audience (AUD) tag of the Access application. */
  audience: string;
  /** Optional extra allow-list checked against the token's email claim. */
  emails?: string[];
}

export type AccessVerifier = (token: string | undefined) => Promise<boolean>;

/**
 * Validates the Cloudflare Access JWT (signature, issuer, audience, expiry).
 * With this in place a leaked tunnel hostname is useless without an Access login.
 */
export function createAccessVerifier(cfg: AccessConfig, keys?: JWTVerifyGetKey): AccessVerifier {
  const issuer = `https://${cfg.teamDomain}`;
  const getKey = keys ?? createRemoteJWKSet(new URL(`${issuer}/cdn-cgi/access/certs`));
  const emails = (cfg.emails ?? []).map((e) => e.toLowerCase());

  return async (token) => {
    if (!token) return false;
    try {
      const { payload } = await jwtVerify(token, getKey, { issuer, audience: cfg.audience, algorithms: ['RS256'] });
      if (emails.length === 0) return true;
      return typeof payload.email === 'string' && emails.includes(payload.email.toLowerCase());
    } catch {
      return false;
    }
  };
}
