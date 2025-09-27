import type { User, Session } from "@app/schema";
import { Sessions, Users } from "@app/schema";
import type { UUID } from "@app/types";
import { db, getFirst } from "@lib/db";
import { env } from "@lib/env";
import { logger } from "@lib/logger";
import { eq } from "drizzle-orm";
import type {
  Request as ExpressRequest,
  Response as ExpressResponse,
  NextFunction,
  Request,
  Response,
} from "express";
import * as jose from "jose";
import { z } from "zod";
import {
  FRONTEND_COOKIE_NAME,
  SESSION_COOKIE_NAME,
  EXPRESS_FRONTEND_COOKIE_OPTIONS,
  EXPRESS_SESSION_COOKIE_OPTIONS,
} from "./constants";
import { JWS_SECRET } from "./jwt-helpers";
import { validateUuid } from "@lib/validate-uuid";

class GoNextError extends Error {
  constructor(...args: ConstructorParameters<typeof Error>) {
    super(...args);
    this.name = "GoNextError";
  }
}

/**
 * Authentication middleware. Does **NOT** guard against unauthenticated
 * Requests. It only sets the `request.user` field to the user object if the
 * user is authenticated.
 *
 * If the user is not authenticated, `request.user` will be `null`.
 *
 * If you want to guard against unauthenticated requests, use the
 * `@ProtectRoute` decorator.
 */
export function auth() {
  return async (request: Request, response: Response, next: NextFunction) => {
    try {
      const ip_address = request.header("x-real-ip");
      if (!ip_address && env.NODE_ENV === "production") {
        logger.warn({
          event: "auth:middleware:missing_real_ip",
          msg: "Missing real IP header",
          real_ip: ip_address,
          x_forwarded_for: request.header("x-forwarded-for"),
        });
        return response.status(400).json({
          error: "Missing real IP header",
        });
      }

      // Initially set to null so we don't forget later
      request.user = null;
      request.session = null;
      request.user_password = null;
      request.auth_method = null;
      request.user_google_id = null;

      const token = await retrieveToken(request);
      request.auth_method = token.type;

      const sessionAndUser = await getSessionAndUser(token);

      const { session, user, passwordHash, googleId } = sessionAndUser;
      request.user = user;
      request.user_password = passwordHash;
      request.session = session;
      request.user_google_id = googleId;

      //#region IP Thing
      // TODO: reenable this after fixing the real-ip issue
      // if (session.ip !== ip_address && env.NODE_ENV === "production") {
      //   const ERR_MSG = "Session IP address does not match request IP address";
      //   await LogOut(response, session_id, {
      //     reason: ERR_MSG,
      //     ip_address,
      //     session_ip: session.ip,
      //   });
      //   return response.status(401).json({
      //     error: ERR_MSG,
      //   });
      // }
      //#endregion

      if (token.type === "jwt") {
        return next();
      }

      if (session && new Date() > session.expiresAt) {
        await logOut(response, token.token, "Session has expired");
        return response.status(401).json({
          error: "Session has expired",
        });
      }

      async function refresh_frontend_token() {
        const user_id = user.id;
        if (!user_id) throw new Error("User ID is missing");

        logger.info({
          event: "auth:middleware:refresh_frontend_token",
          user_id,
          ip_address,
          msg: `Refreshing frontend token for ${user_id}`,
        });
        const new_fe_cookie = await newFrontendJwt(user_id);
        response.cookie(
          FRONTEND_COOKIE_NAME,
          new_fe_cookie,
          EXPRESS_FRONTEND_COOKIE_OPTIONS,
        );
      }

      const fe_cookie = request.cookies[FRONTEND_COOKIE_NAME];

      const { payload: claims } = await jose
        .jwtVerify(fe_cookie, JWS_SECRET)
        .catch((error) => {
          logger.error({
            event: "auth:middleware:jwt_verify_error",
            msg: `Error verifying JWT; failed cookie: ${fe_cookie}`,
            error: error,
          });
          return { payload: null };
        });

      // it's cleaner
      // prettier-ignore
      const is_about_to_expire =
        claims?.exp !== undefined &&
        claims.exp - Date.now() / 1000 < 5 * 60;

      if (!claims || is_about_to_expire) {
        await refresh_frontend_token();
      }

      logger.trace({
        event: "auth:middleware:authenticated",
        user_id: user.id,
        ip_address,
        msg: "User authenticated",
        session_id: token,
        path: request.path,
      });

      next();
    } catch (error) {
      if (error instanceof GoNextError) {
        return next();
      }

      if (request.path.startsWith("/auth")) {
        logger.error({
          event: "auth:middleware:error:ignored",
          msg: "Unexpected error in auth middleware. Ignored because it happened in an auth route",
          path: request.path,
          error,
        });
        return next();
      }

      logger.error({
        event: "auth:middleware:error",
        msg: "Unhandled error in auth middleware",
        error,
      });
      return response.status(500).json({
        error: `Internal Server Error: ${error}`,
      });
    }
  };
}

/**
 * Logs out a user by invalidating their session.
 * @param response The Express response object
 * @param session_id The session ID to invalidate
 * @param reason The reason for logging out the user
 */
async function logOut(
  response: ExpressResponse,
  session_id: UUID,
  reason: string,
) {
  if (session_id) {
    await db
      .update(Sessions)
      .set({
        forceExpire: true,
        reasonForceExpire: reason,
      })
      .where(eq(Sessions.id, session_id))
      .catch((error) => {
        logger.error(error, "Failed to update session");
        throw new Error("Failed to update session", {
          cause: error,
        });
      });
  }
  response.clearCookie(SESSION_COOKIE_NAME, EXPRESS_SESSION_COOKIE_OPTIONS);
  response.clearCookie(FRONTEND_COOKIE_NAME, EXPRESS_FRONTEND_COOKIE_OPTIONS);
}

/**
 * Discriminated union type for the different types of tokens that can be
 * retrieved.
 */
type Token =
  | {
      type: "session";
      token: string;
    }
  | {
      type: "jwt";
      token: string;
    };

async function retrieveToken(request: ExpressRequest): Promise<Token> {
  if (request.cookies[SESSION_COOKIE_NAME]) {
    return {
      type: "session",
      token: request.cookies[SESSION_COOKIE_NAME],
    };
  }

  const authHeader = request.header("authorization");

  if (authHeader) {
    const isBearerToken = authHeader.toLowerCase().startsWith("bearer ");
    const token = isBearerToken ? authHeader.split(" ")[1] : authHeader;

    if (validateUuid(token)) {
      return { type: "session", token };
    }

    if (token.includes(".")) {
      return { type: "jwt", token };
    }

    if (isBearerToken) {
      throw new GoNextError("Invalid token format");
    }
  }

  throw new GoNextError("No token found");
}

type SessionAndUser = {
  session: Pick<
    Session,
    "userId" | "id" | "ipAddress" | "createdAt" | "expiresAt"
  > | null;
  user: Omit<User, "passwordHash">;
  googleId: string | null;
  passwordHash: string | null;
};

async function getSessionAndUser(token: Token): Promise<SessionAndUser> {
  switch (token.type) {
    case "session": {
      return retrieveSession(token.token);
    }
    case "jwt": {
      return retrieveUserFromJwt(token.token);
    }
  }
}

async function retrieveSession(session_id: UUID): Promise<SessionAndUser> {
  const session = await db
    .select({
      user: Users,
      session: {
        userId: Sessions.userId,
        id: Sessions.id,
        createdAt: Sessions.createdAt,
        expiresAt: Sessions.expiresAt,
        ipAddress: Sessions.ipAddress,

        forceExpire: Sessions.forceExpire,
        reasonForceExpire: Sessions.reasonForceExpire,
      },
    })
    .from(Sessions)
    .where(eq(Sessions.id, session_id))
    .leftJoin(Users, eq(Sessions.userId, Users.id))
    .then(getFirst);

  if (!session || !session.user) {
    throw new Error("Session not found");
  }

  const { user: user_, session: session_data } = session;
  const { passwordHash, ...user } = user_;

  return {
    user,
    passwordHash,
    googleId: user.googleId,
    session: session_data,
  };
}

async function retrieveUserFromJwt(jwt: string): Promise<SessionAndUser> {
  const decoded_ = await jose.jwtVerify(jwt, JWS_SECRET);
  const decoded = DecodedJwtSchema.parse(decoded_.payload);

  const user_id = decoded.sub;

  const user_ = await db
    .select()
    .from(Users)
    .where(eq(Users.id, user_id))
    .then(getFirst);

  if (!user_) {
    throw new Error("User not found");
  }

  const { passwordHash, ...user } = user_;

  return {
    user,
    passwordHash,
    googleId: user.googleId,
    session: null,
  };
}

async function newFrontendJwt(user_id: string) {
  const new_fe_cookie = await new jose.SignJWT()
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(user_id)

    .setIssuedAt()
    .setExpirationTime("30d")

    .setIssuer(env.API_URL.toString())
    .setAudience(env.FRONTEND_URL.toString())
    .setJti(crypto.randomUUID())
    .sign(JWS_SECRET);

  return new_fe_cookie;
}

const DecodedJwtSchema = z.object({
  sub: z.string(),
  iat: z.number(),
  exp: z.number(),
  iss: z.string(),
  aud: z.string(),
  jti: z.string(),
});
