import * as crypto from 'node:crypto';
import * as util from 'node:util';

import sessionMiddleware from '../shared/session.js';
import paramsMiddleware from '../shared/assemble_params.js';
import bodyParser from '../shared/conditional_body.js';
import rejectDupes from '../shared/reject_dupes.js';
import instance from '../helpers/weak_cache.js';
import { InvalidClient, InvalidRequest } from '../helpers/errors.js';
import * as formHtml from '../helpers/user_code_form.js';
import formPost from '../response_modes/form_post.js';
import { normalize, denormalize } from '../helpers/user_codes.js';
import {
  NoCodeError, NotFoundError, ExpiredError, AlreadyUsedError, AbortedError,
} from '../helpers/re_render_errors.js';

const parseBody = bodyParser.bind(undefined, 'application/x-www-form-urlencoded');
const randomFill = util.promisify(crypto.randomFill);

export const get = [
  sessionMiddleware,
  paramsMiddleware.bind(undefined, new Set(['user_code'])),
  async function renderCodeVerification(ctx, next) {
    const {
      features: { deviceFlow: { charset, userCodeInputSource } },
    } = instance(ctx.oidc.provider).configuration();

    // TODO: generic xsrf middleware to remove this
    let secret = Buffer.allocUnsafe(24);
    await randomFill(secret);
    secret = secret.toString('hex');
    ctx.oidc.session.state = { secret };

    const action = ctx.oidc.urlFor('code_verification');
    if (ctx.oidc.params.user_code) {
      formPost(ctx, action, {
        xsrf: secret,
        user_code: ctx.oidc.params.user_code,
      });
    } else {
      await userCodeInputSource(ctx, formHtml.input(action, secret, undefined, charset));
    }

    await next();
  },
];

export const post = [
  sessionMiddleware,
  parseBody,
  paramsMiddleware.bind(undefined, new Set(['xsrf', 'user_code', 'confirm', 'abort'])),
  rejectDupes.bind(undefined, {}),

  async function codeVerificationCSRF(ctx, next) {
    if (!ctx.oidc.session.state) {
      throw new InvalidRequest('could not find device form details');
    }
    if (ctx.oidc.session.state.secret !== ctx.oidc.params.xsrf) {
      throw new InvalidRequest('xsrf token invalid');
    }
    await next();
  },

  async function loadDeviceCodeByUserInput(ctx, next) {
    const { userCodeConfirmSource, mask } = instance(ctx.oidc.provider).configuration('features.deviceFlow');
    const { user_code: userCode, confirm, abort } = ctx.oidc.params;

    if (!userCode) {
      throw new NoCodeError();
    }

    const normalized = normalize(userCode);
    const code = await ctx.oidc.provider.DeviceCode.findByUserCode(
      normalized,
      { ignoreExpiration: true },
    );

    if (!code) {
      throw new NotFoundError(userCode);
    }

    if (code.isExpired) {
      throw new ExpiredError(userCode);
    }

    if (code.error || code.accountId || code.inFlight) {
      throw new AlreadyUsedError(userCode);
    }

    ctx.oidc.entity('DeviceCode', code);

    if (abort) {
      Object.assign(code, {
        error: 'access_denied',
        errorDescription: 'End-User aborted interaction',
      });

      await code.save();
      throw new AbortedError();
    }

    if (!confirm) {
      const client = await ctx.oidc.provider.Client.find(code.clientId);
      if (!client) {
        throw new InvalidClient('client is invalid', 'client not found');
      }
      ctx.oidc.entity('Client', client);

      const action = ctx.oidc.urlFor('code_verification');
      await userCodeConfirmSource(
        ctx,
        formHtml.confirm(action, ctx.oidc.session.state.secret, userCode),
        client,
        code.deviceInfo,
        denormalize(normalized, mask),
      );
      return;
    }

    code.inFlight = true;
    await code.save();

    await next();
  },

  function cleanup(ctx, next) {
    ctx.oidc.session.state = undefined;
    return next();
  },
];
