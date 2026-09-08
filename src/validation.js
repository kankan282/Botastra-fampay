import { z } from 'zod';

const amountSchema = z.coerce.number().positive().max(1_000_000).refine(
  (value) => Math.abs(value * 100 - Math.round(value * 100)) < 1e-8,
  'Amount can have at most two decimal places.',
);

const upiSchema = z.string().trim().min(3).max(320).regex(
  /^[a-zA-Z0-9._+\-]{2,256}@[a-zA-Z0-9._\-]{2,64}$/,
  'Enter a valid UPI ID such as name@fam.',
);

const gmailSchema = z.string().trim().toLowerCase().email().max(254);
const appPasswordSchema = z.string().trim().min(8).max(100).transform((value) => value.replace(/\s/g, ''));
const labelSchema = z.string().trim().min(2).max(80);

export const publicKeySchema = z.object({
  label: labelSchema,
  contact_email: z.union([z.literal(''), z.string().trim().toLowerCase().email().max(254)]).optional().default(''),
  gmail: gmailSchema,
  gmail_app_password: appPasswordSchema,
  default_upi_id: upiSchema,
  payee_name: z.string().trim().min(2).max(100),
  allowed_senders: z.union([z.string().max(1000), z.array(z.string().max(254)).max(10)]).optional().default(''),
  expires_in_days: z.coerce.number().int().min(1).max(365).optional(),
  setup_access_code: z.string().max(200).optional().default(''),
  consent: z.literal(true),
}).strict();

export const adminKeySchema = z.object({
  label: labelSchema,
  contact_email: z.union([z.literal(''), z.string().trim().toLowerCase().email().max(254)]).optional().default(''),
  gmail: z.union([z.literal(''), gmailSchema]).optional().default(''),
  gmail_app_password: z.string().max(100).optional().default('').transform((value) => value.replace(/\s/g, '')),
  default_upi_id: z.union([z.literal(''), upiSchema]).optional().default(''),
  payee_name: z.string().trim().max(100).optional().default(''),
  allowed_senders: z.union([z.string().max(1000), z.array(z.string().max(254)).max(10)]).optional().default(''),
  expires_in_hours: z.coerce.number().int().min(1).max(87_600).default(168),
  scopes: z.array(z.enum(['qr', 'verify'])).min(1).max(2).default(['qr', 'verify']),
}).strict().superRefine((value, context) => {
  if (value.scopes.includes('verify')) {
    if (!value.gmail) context.addIssue({ code: 'custom', path: ['gmail'], message: 'Gmail is required for the verify scope.' });
    if (value.gmail_app_password.length < 8) context.addIssue({ code: 'custom', path: ['gmail_app_password'], message: 'A Gmail App Password is required for the verify scope.' });
  }
});

export const qrSchema = z.object({
  amount: amountSchema,
  upi_id: upiSchema.optional(),
  payee_name: z.string().trim().min(2).max(100).optional(),
  note: z.string().trim().max(80).optional(),
}).strict();

export const verifySchema = z.object({
  amount: amountSchema,
  utr: z.string().trim().regex(/^\d{12}$/, 'UTR must contain exactly 12 digits.').optional(),
  txnid: z.string().trim().min(6).max(100).regex(/^[a-zA-Z0-9._\-]+$/).optional(),
}).strict();

export const extendSchema = z.object({
  hours: z.coerce.number().int().min(1).max(87_600),
}).strict();

export const rotateSchema = z.object({
  expires_in_hours: z.coerce.number().int().min(1).max(87_600).optional(),
}).strict();

export function zodError(error) {
  return error.issues.map((issue) => ({ field: issue.path.join('.') || 'body', message: issue.message }));
}
