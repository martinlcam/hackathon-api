import argon2 from "@node-rs/argon2";
import { Body, Post, Queries, Route } from "tsoa";
import { eq } from "drizzle-orm";
import * as jose from "jose";

import { logger } from "@lib/logger";
import { DAY } from "@lib/constants";
import { ErrorBadRequest } from "@lib/status/error";
import { db, getFirst } from "@lib/db";
import { Sessions, Users } from "@app/schema";
import {
  FRONTEND_COOKIE_NAME,
  FRONTEND_COOKIE_OPTIONS,
  SESSION_COOKIE_NAME,
  SESSION_COOKIE_OPTIONS,
} from "../constants";

import { Z_RedirectQuery } from "../types";
import { env } from "@lib/env";
import { JWS_SECRET } from "../jwt-helpers";
import { NController } from "@lib/ncontroller";

type LoginBody = {
  email: string;
  password: string;
};

@Route("/auth/v1/login")
export class LoginPasswordController extends NController {
  @Post("/password")
  async login_password(
    @Body() body: LoginBody,
    @Queries()
    _query: {
      success_url: string;
      error_url: string;
    },
  ) {
    const { success_url, error_url } = Z_RedirectQuery.parse(_query);

    const ipAddress = this.getRealIp();
    try {
      this.clearCookie(SESSION_COOKIE_NAME);
      this.clearCookie(FRONTEND_COOKIE_NAME);

      const user = await db
        .select()
        .from(Users)
        .where(eq(Users.email, body.email))
        .then(getFirst);

      if (!user) {
        this.redirect(error_url + "?error=user_not_found");
        return;
      }

      const is_valid =
        user.passwordHash &&
        (await argon2.verify(user.passwordHash, body.password));

      if (!is_valid) {
        this.redirect(error_url + "?error=invalid_password");
        return;
      }

      const iat = new Date();
      const exp = new Date(iat.getTime() + 30 * DAY); // 30 days
      const session = await db
        .insert(Sessions)
        .values({
          userId: user.id,
          createdAt: iat,
          expiresAt: exp,
          ipAddress,
        })
        .returning()
        .then(getFirst);

      if (!session) {
        throw new ErrorBadRequest("Failed to create session");
      }
      const fe_jwt = await new jose.SignJWT()
        .setProtectedHeader({ alg: "HS256" })
        .setSubject(user.id)

        .setIssuedAt(iat)
        .setExpirationTime(exp)

        .setIssuer(env.API_URL.toString())
        .setAudience(env.FRONTEND_URL.toString())
        .setJti(crypto.randomUUID())
        .sign(JWS_SECRET);

      this.setCookie(SESSION_COOKIE_NAME, session.id, SESSION_COOKIE_OPTIONS);
      this.setCookie(FRONTEND_COOKIE_NAME, fe_jwt, FRONTEND_COOKIE_OPTIONS);

      logger.info({
        event: "auth:login_password",
        user_id: user.id,
        ip_address: ipAddress,
        msg: "User logged in successfully",
      });

      this.redirect(success_url + "?login=successful");
    } catch (error) {
      logger.error({ err: error }, "Error in login_password");
      this.redirect(error_url + "?error=auth_failed");
    }
  }
}
