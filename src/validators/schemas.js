const { z } = require('zod');

const issueSchema = z.object({
  sub: z.string().optional(),
  aud: z.string().optional(),
  ttl: z.number().int().positive().optional(),
  claims: z.record(z.any()).optional(),
  purpose: z.enum(['local', 'public']).optional(),
  issueRefresh: z.boolean().optional(),
  footer: z.any().optional(),
  implicitAssertion: z.string().optional()
});

const verifySchema = z.object({
  token: z.string().min(1),
  aud: z.string().optional(),
  implicitAssertion: z.string().optional()
});

const refreshSchema = z.object({
  refreshToken: z.string().min(1),
  purpose: z.enum(['local', 'public']).optional(),
  ttl: z.number().int().positive().optional(),
  claims: z.record(z.any()).optional(),
  implicitAssertion: z.string().optional()
});

const revokeSchema = z.object({
  token: z.string().optional(),
  jti: z.string().optional()
}).refine(data => data.token || data.jti, {
  message: 'Must provide either token or jti'
});

const introspectSchema = z.object({
  token: z.string().min(1),
  implicitAssertion: z.string().optional()
});

const rotateSchema = z.object({
  purpose: z.enum(['local', 'public']),
  gracePeriod: z.number().int().nonnegative().optional()
});

function validate(schema) {
  return (req, res, next) => {
    try {
      req.body = schema.parse(req.body);
      next();
    } catch (err) {
      next(err); // Central error handler catches ZodError
    }
  };
}

module.exports = {
  issueSchema,
  verifySchema,
  refreshSchema,
  revokeSchema,
  introspectSchema,
  rotateSchema,
  validate
};
