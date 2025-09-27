import { Session } from "@app/schema/sessions";
import { User } from "@app/schema/users";

declare global {
  namespace Express {
    interface Request {
      // for auth
      user: Omit<User, "password_hash"> | null;
      user_password: string | null;
      session: Pick<
        Session,
        "userId" | "id" | "ipAddress" | "createdAt" | "expiresAt"
      > | null;
      user_google_id: string | null;
      auth_method: "session" | "jwt" | null;

      // for tracing
      tracing: {
        timestamp: number;
        request_id: string;
        path: string;
        method: string;
        client_ip: string;
      };
    }
  }
}
