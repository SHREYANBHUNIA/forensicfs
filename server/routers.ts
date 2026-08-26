import { COOKIE_NAME } from "@shared/const";
import { z } from "zod";
import { getSessionCookieOptions } from "./_core/cookies";
import { systemRouter } from "./_core/systemRouter";
import { protectedProcedure, publicProcedure, router } from "./_core/trpc";
import { completeEvidenceUpload, issueEvidenceUpload } from "./forensicUpload";
import { getForensicWorkspace } from "./forensicWorkspace";

export const appRouter = router({
    // if you need to use socket.io, read and register route in server/_core/index.ts, all api should start with '/api/' so that the gateway can route correctly
  system: systemRouter,
  auth: router({
    me: publicProcedure.query(opts => opts.ctx.user),
    logout: publicProcedure.mutation(({ ctx }) => {
      const cookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 });
      return {
        success: true,
      } as const;
    }),
  }),
  forensic: router({
    workspace: publicProcedure
      .input(z.object({ caseId: z.string().min(1).optional() }).optional())
      .query(() => getForensicWorkspace()),
    createEvidenceUpload: protectedProcedure
      .input(z.object({ fileName: z.string().min(1).max(255), sizeBytes: z.number().int().positive(), mediaType: z.string().max(100).optional().default("application/octet-stream") }))
      .mutation(({ ctx, input }) => issueEvidenceUpload(ctx.user.id, input)),
    completeEvidenceUpload: protectedProcedure
      .input(z.object({ receipt: z.string().min(20), sha256: z.string().regex(/^[a-fA-F0-9]{64}$/) }))
      .mutation(({ ctx, input }) => completeEvidenceUpload(ctx.user.id, input.receipt, input.sha256)),
  }),
});

export type AppRouter = typeof appRouter;
