import { DisclosureFrame } from '@sd-jwt/types';
import { KeyObject, X509Certificate, createHash, createSign } from 'crypto';
import { base64urlEncode } from '@sd-jwt/utils';
import { ALGORITHMS } from './constant';

export type ProtectedHeader = {
  alg: Alg;
  typ?: string;

  // TODO: define other headers
  [key: string]: unknown;
};

export type SigD = {
  mId: string;
  pars: [string, string];
  hash: string;
};

export type Alg = keyof typeof ALGORITHMS;

export type GeneralJWS = {
  payload: string | Record<string, unknown>;
  signatures: Array<{
    protected: string;
    signature: string;

    /**
     * This is a optional unprotected header.
     *
     */
    header?: {
      disclosures?: Array<string>;
      kid?: string;
      kb_jwt?: string;
    };
  }>;
};

export class Sign<T extends Record<string, unknown>> {
  private readonly serialized?: GeneralJWS;

  private protectedHeader: Partial<ProtectedHeader>;

  /**
   * If undefined, the default disclosure frame will be used.
   * which is set disclosures for every 1-depth property of the payload.
   */
  private disclosureFrame: DisclosureFrame<T> | undefined;

  /**
   * If payload is empty, the data of payload will be empty string.
   * This is the Detached JWS Payload described in TS 119 182-1 v1.2.1 section 5.2.8
   * The sigD header must be present when the payload is empty.
   */
  constructor(private readonly payload?: T) {
    this.protectedHeader = {};
  }

  async sign(key: KeyObject) {
    if (
      !this.protectedHeader.alg ||
      (this.protectedHeader.alg as any) === 'none'
    ) {
      throw new Error('alg must be set and not "none"');
    }

    if (this.serialized !== undefined) {
      // TODO: implement
      // Add signature in serialized
    }

    if (this.payload === undefined) {
      /**
       * If the payload is empty, It uses Detached JWS Payload described in TS 119 182-1 v1.2.1 section 5.2.8
       * So Create manual signature here.
       */

      const encodedProtectedHeader = base64urlEncode(
        JSON.stringify(this.protectedHeader),
      );
      const encodedPayload = '';
      const protectedData = `${encodedProtectedHeader}.${encodedPayload}`;

      const signature = JWTSigner.sign(
        this.protectedHeader.alg,
        protectedData,
        key,
      );
    } else {
      /**
       * Create a General JWS Payload with SD-JWT library.
       */
    }

    return this;
  }

  setProtectedHeader(header: ProtectedHeader) {
    if (!header.alg || (header.alg as any) === 'none') {
      throw new Error('alg must be set and not "none"');
    }
    this.protectedHeader = header;
    return this;
  }

  setDisclosureFrame(frame: DisclosureFrame<T>) {
    this.disclosureFrame = frame;
    return this;
  }

  setB64(b64: boolean) {
    if (b64) {
      this.protectedHeader.b64 = undefined;
    } else {
      this.protectedHeader.b64 = false;
    }
    return this;
  }

  setIssuedAt(sec?: number) {
    this.protectedHeader.iat = sec ?? Math.floor(Date.now() / 1000);
    return this;
  }

  setSignedAt(sec?: number) {
    this.protectedHeader.signedAt = sec ?? Math.floor(Date.now() / 1000);
    return this;
  }

  setSigD(sigd: SigD) {
    this.protectedHeader.sigD = sigd;
    /**
     * TS 119 182-1 v1.2.1 section 5.1.10
     * 
     * If the sigD header parameter is present with its member set to
      "http://uri.etsi.org/19182/HttpHeaders" then the b64 header parameter shall be present and set to
      "false".
     */
    if (sigd.mId === 'http://uri.etsi.org/19182/HttpHeaders') {
      this.setB64(false);
    }
    return this;
  }

  setJti(jti: string) {
    this.protectedHeader.jti = jti;
    return this;
  }

  setX5u(uri: string) {
    this.protectedHeader.x5u = uri;
    return this;
  }

  setX5c(certs: X509Certificate[]) {
    this.protectedHeader.x5c = certs.map((cert) => cert.raw.toString('base64'));
    return this;
  }

  setX5tS256(cert: X509Certificate) {
    this.protectedHeader['x5t#256'] = createHash('sha-256')
      .update(cert.raw)
      .digest('base64url');
    return this;
  }

  setX5tSo(cert: X509Certificate) {
    this.protectedHeader['x5t#o'] = {
      digAlg: 'sha-512',
      digVal: createHash('sha-512').update(cert.raw).digest('base64url'),
    };
    return this;
  }

  setX5ts(certs: X509Certificate[]) {
    if (certs.length < 2) {
      throw new Error(
        'at least 2 certificates are required, use setX5tSo instead',
      );
    }
    this.protectedHeader['x5t#s'] = certs.map((cert) => ({
      digAlg: 'sha-512',
      digVal: createHash('sha-512').update(cert.raw).digest('base64url'),
    }));
    return this;
  }

  setCty(cty: string) {
    this.protectedHeader.cty = cty;
    return this;
  }

  setKid(kid: string) {
    this.protectedHeader.kid = kid;
    return this;
  }

  toJSON() {
    if (!this.serialized) {
      throw new Error('Not signed yet');
    }
    return this.serialized;
  }
}

class JWTSigner {
  static sign(alg: Alg, signingInput: string, privateKey: KeyObject) {
    const signature = this.createSignature(alg, signingInput, privateKey);
    return signature;
  }

  static createSignature(
    alg: Alg,
    signingInput: string,
    privateKey: KeyObject,
  ) {
    switch (alg) {
      case 'RS256':
      case 'RS384':
      case 'RS512':
      case 'PS256':
      case 'PS384':
      case 'PS512': {
        const option = ALGORITHMS[alg];
        return this.createRSASignature(signingInput, privateKey, option);
      }
      case 'ES256':
      case 'ES384':
      case 'ES512': {
        const option = ALGORITHMS[alg];
        return this.createECDSASignature(signingInput, privateKey, option);
      }
      case 'EdDSA': {
        const option = ALGORITHMS[alg];
        return this.createEdDSASignature(signingInput, privateKey, option);
      }
      default:
    }
    throw new Error(`Unsupported algorithm: ${alg}`);
  }

  static createRSASignature(
    signingInput: string,
    privateKey: KeyObject,
    options: { hash: string; padding: number },
  ) {
    const signer = createSign(options.hash);
    signer.update(signingInput);
    const signature = signer.sign({
      key: privateKey,
      padding: options.padding,
    });
    return signature.toString('base64url');
  }

  static createECDSASignature(
    signingInput: string,
    privateKey: KeyObject,
    options: { hash: string; namedCurve: string },
  ) {
    const signer = createSign(options.hash);
    signer.update(signingInput);

    let signature = signer.sign({
      key: privateKey,
      dsaEncoding: 'ieee-p1363',
    });

    return signature.toString('base64url');
  }

  static createEdDSASignature(
    signingInput: string,
    privateKey: KeyObject,
    options: { curves: string[] },
  ) {
    const signer = createSign(options.curves[0]);
    signer.update(signingInput);
    const signature = signer.sign({
      key: privateKey,
    });
    return signature.toString('base64url');
  }
}
