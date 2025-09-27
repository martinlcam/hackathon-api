import { Body, Header, Post, Queries, Route } from "tsoa";
import * as jose from "jose";

import { Users } from "@app/schema/user.schema";
import { db, getFirst } from "@lib/db";
import { ErrorForbidden, InternalServerError } from "@lib/status/error";
import { DAY } from "@lib/constants";
import { Sessions } from "@app/schema/session.schema";
import {
  FRONTEND_COOKIE_NAME,
  FRONTEND_COOKIE_OPTIONS,
  SESSION_COOKIE_NAME,
  SESSION_COOKIE_OPTIONS,
} from "../constants";
import { logger } from "@lib/logger";
import { env } from "@lib/env";
import { JWS_SECRET } from "../jwt-helpers";
import { Z_RedirectQuery } from "../types";
import { NController } from "@lib/ncontroller";

import { OAuth2Client } from "google-auth-library";
const client = new OAuth2Client(env.GOOGLE_CLIENT_ID);

type SignInWithGoogleBody = {
  idToken: string;
};

@Route("/auth/v2/google")
export class V2GoogleController extends NController {
  @Post("/callback")
  public async signInWithGoogle(
    @Body() body: SignInWithGoogleBody,
    @Queries()
    _query: {
      success_url?: string;
      error_url?: string;
      inviteCode?: string;
    },
    @Header("x-real-ip") ip_address?: string,
  ) {
    const randInt = Math.floor(Math.random() * 100);
    const { success_url, error_url } = Z_RedirectQuery.parse(_query);
    const { idToken } = body;

    try {
      // Logout any existing sessions
      this.clearCookie(SESSION_COOKIE_NAME);
      this.clearCookie(FRONTEND_COOKIE_NAME);

      const ticket = await client.verifyIdToken({
        idToken,
        audience: process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID,
      });

      const payload = ticket.getPayload();
      if (!payload) {
        throw new Error("Invalid Google token");
      }
      // console.log("payload", payload);
      const email = payload.email;
      const googleId = payload.sub;

      if (!email || !googleId) {
        throw new ErrorForbidden("Invalid Google token");
      }
      // Validate signup invite code if provided

      const user = await db
        .insert(Users)
        .values({
          email: email,
          name: payload.name || email,
          googleId: googleId,
          imageUrl: payload.picture,
          isEmailVerified: payload.email_verified || false,
        })
        .returning()
        .onConflictDoUpdate({
          target: Users.email,
          set: {
            googleId: googleId,
          },
        })
        .then(getFirst);

      if (!user) {
        // todo: maybe add error logging here
        throw new InternalServerError("Failed to create user");
      }

      // Increment invite usage after successful user creation (if invite code was provided)
      const iat = new Date();
      const exp = new Date(iat.getTime() + 30 * DAY);

      const session = await db
        .insert(Sessions)
        .values({
          userId: user.id,
          createdAt: iat,
          expiresAt: exp,
          ipAddress: ip_address || "",
        })
        .returning()
        .then(getFirst);

      if (!session) {
        throw new InternalServerError("Failed to create session");
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
        event: "auth:sign_in_with_google",
        user_id: user.id,
        ip_address,
        msg: "User signed in with google",
      });

      if (success_url) {
        const url = new URL(success_url);
        url.searchParams.set("google", "successful");
        url.searchParams.set("debugRng", randInt.toString());
        this.redirect(url.toString());
      }
    } catch (error) {
      if (error_url) {
        const url = new URL(error_url);
        url.searchParams.set("error", "auth_failed");
        url.searchParams.set("debugRng", randInt.toString());

        if (success_url) {
          url.searchParams.set("redirect_url", success_url.toString());
        }

        logger.error({ err: error }, "Error in sign_in_with_google");
        this.redirect(url.toString());
      }
    }
    return;
  }
}
