import { Injectable } from '@nestjs/common';

import {
  Token,
  ProtectedHeaders,
  parseCerts,
  generateX5c,
  UnprotectedHeaders,
} from '@xevolab/jades';
import { createPrivateKey } from 'crypto';
import * as fs from 'fs';

@Injectable()
export class AppService {
  async credential() {
    const payload = {
      hello: 'world',
    };

    const key = createPrivateKey({
      key: fs.readFileSync('private-key.pem', 'utf8'),
      format: 'pem',
      type: 'pkcs1',
    });
    const certs = parseCerts(fs.readFileSync('certificate.pem', 'utf8'));

    const jades = new Token(payload);

    jades.setProtectedHeaders(
      new ProtectedHeaders({
        x5c: generateX5c(certs),
      }),
    );

    const unprotectedHeaders = new UnprotectedHeaders({
      etsiU: [
        {
          sigTst: {
            tstTokens: [
              {
                val: 'The Time Stamp Token (TST)',
              },
            ],
          },
        },
      ],
    });

    jades.setUnprotectedHeaders(unprotectedHeaders);
    jades.sign('RS256', key);

    const token = jades.toString();
    const obj = jades.toObject();
    console.log(obj);
    return token;
  }
}
