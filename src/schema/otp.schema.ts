import { pgTable, text, timestamp, uuid, varchar } from "drizzle-orm/pg-core";

export const OneTimePins = pgTable("one_time_pins", {
  id: uuid("id").primaryKey().notNull().defaultRandom(),
  email: varchar("email").notNull(),
  hash: text("hash").notNull(),
  created_at: timestamp("created_at").notNull().defaultNow(),
  verified_at: timestamp("verified_at"),

  deleted_reason: text("deleted_reason"),
});

export type OneTimePin = typeof OneTimePins.$inferSelect;
export type InsertOneTimePin = typeof OneTimePins.$inferInsert;
