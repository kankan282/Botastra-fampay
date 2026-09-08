export function openApiDocument(baseUrl = '') {
  return {
    openapi: '3.1.0',
    info: {
      title: 'BotAstra FamPay Verify API',
      version: '1.0.0',
      description: 'Generate UPI QR codes and verify trusted FamPay/FamApp payment-alert emails. Owner: @botastra. This project is not affiliated with FamPay/FamApp.',
      license: { name: 'MIT', url: 'https://opensource.org/license/mit' },
    },
    servers: [{ url: baseUrl || '/' }],
    tags: [
      { name: 'Key', description: 'API-key status and self-service issue endpoint.' },
      { name: 'Payments', description: 'UPI QR generation and payment verification.' },
      { name: 'Admin', description: 'ADMIN_TOKEN-protected key administration.' },
    ],
    components: {
      securitySchemes: {
        ApiKey: { type: 'apiKey', in: 'header', name: 'X-API-Key' },
        AdminBearer: { type: 'http', scheme: 'bearer', bearerFormat: 'ADMIN_TOKEN' },
      },
      schemas: {
        ApiError: {
          type: 'object',
          properties: {
            ok: { type: 'boolean', const: false },
            error: {
              type: 'object',
              properties: { code: { type: 'string' }, message: { type: 'string' }, details: { type: 'array' } },
            },
          },
        },
        QrRequest: {
          type: 'object', required: ['amount'], additionalProperties: false,
          properties: {
            amount: { type: 'number', minimum: 0.01, maximum: 1000000, example: 25.01 },
            upi_id: { type: 'string', example: 'merchant@fam', description: 'Optional when a default is saved on the key.' },
            payee_name: { type: 'string', example: 'Demo Merchant' },
            note: { type: 'string', maxLength: 80 },
          },
        },
        VerifyRequest: {
          type: 'object', required: ['amount'], additionalProperties: false,
          properties: {
            amount: { type: 'number', minimum: 0.01, example: 25.01 },
            utr: { type: 'string', pattern: '^\\d{12}$', example: '123456789012' },
            txnid: { type: 'string', minLength: 6 },
          },
        },
      },
    },
    paths: {
      '/healthz': {
        get: { summary: 'Health check', responses: { 200: { description: 'Healthy' } } },
      },
      '/api/v1/keys': {
        post: {
          tags: ['Key'], summary: 'Create a self-service expiring API key',
          description: 'Available only when PUBLIC_KEY_CREATION=true. The plaintext API key is returned once.',
          requestBody: { required: true, content: { 'application/json': { schema: { type: 'object' } } } },
          responses: { 201: { description: 'Key issued' }, 400: { description: 'Validation failed' }, 403: { description: 'Self-service disabled' } },
        },
      },
      '/api/v1/key': {
        get: {
          tags: ['Key'], summary: 'Inspect the current API key', security: [{ ApiKey: [] }],
          responses: { 200: { description: 'Current key status' }, 401: { description: 'Invalid key' }, 403: { description: 'Expired or revoked key' } },
        },
      },
      '/api/v1/qr': {
        post: {
          tags: ['Payments'], summary: 'Generate a UPI URI and QR image', security: [{ ApiKey: [] }],
          requestBody: { required: true, content: { 'application/json': { schema: { $ref: '#/components/schemas/QrRequest' } } } },
          responses: { 200: { description: 'QR generated' }, 400: { description: 'Invalid request' }, 403: { description: 'Key unavailable or missing scope' } },
        },
      },
      '/api/v1/verify': {
        post: {
          tags: ['Payments'], summary: 'Verify a payment from trusted Gmail alerts', security: [{ ApiKey: [] }],
          requestBody: { required: true, content: { 'application/json': { schema: { $ref: '#/components/schemas/VerifyRequest' } } } },
          responses: { 200: { description: 'Verification completed (inspect verified)' }, 400: { description: 'Invalid request' }, 403: { description: 'Key unavailable or missing scope' } },
        },
      },
      '/api/v1/admin/keys': {
        get: { tags: ['Admin'], summary: 'List keys', security: [{ AdminBearer: [] }], responses: { 200: { description: 'Key list' } } },
        post: { tags: ['Admin'], summary: 'Issue an expiring key', security: [{ AdminBearer: [] }], responses: { 201: { description: 'Key issued; plaintext returned once' } } },
      },
      '/api/v1/admin/keys/{id}/revoke': {
        post: {
          tags: ['Admin'], summary: 'Revoke a key', security: [{ AdminBearer: [] }],
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } }],
          responses: { 200: { description: 'Revoked' }, 404: { description: 'Not found' } },
        },
      },
      '/api/v1/admin/keys/{id}/extend': {
        post: {
          tags: ['Admin'], summary: 'Extend a key expiry', security: [{ AdminBearer: [] }],
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } }],
          requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['hours'], properties: { hours: { type: 'integer', minimum: 1 } } } } } },
          responses: { 200: { description: 'Expiry extended' } },
        },
      },
      '/api/v1/admin/keys/{id}/rotate': {
        post: {
          tags: ['Admin'], summary: 'Rotate a key and revoke the old one', security: [{ AdminBearer: [] }],
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } }],
          responses: { 201: { description: 'Replacement plaintext key returned once' } },
        },
      },
    },
  };
}
