/**
 * Security Rule Test Suite for JANY BEAUTY
 * Verifies that the Eight Pillars and "Dirty Dozen" attack vectors are blocked with PERMISSION_DENIED.
 */

export interface TestPayload {
  name: string;
  operation: 'create' | 'update' | 'delete' | 'get' | 'list';
  path: string;
  data?: any;
  auth?: { uid: string; email?: string; emailVerified?: boolean } | null;
  expectedResult: 'PERMISSION_DENIED' | 'ALLOWED';
}

export const DIRTY_DOZEN_TESTS: TestPayload[] = [
  {
    name: '1. Shadow Field Injection (Unauthorized key isFree)',
    operation: 'create',
    path: 'products/prod_hack_1',
    data: { id: 'prod_hack_1', title: 'Batom Matte', price: 'R$ 49,90', isFree: true },
    auth: { uid: 'admin_1', email: 'mackson.weiber13@gmail.com', emailVerified: true },
    expectedResult: 'PERMISSION_DENIED'
  },
  {
    name: '2. Oversized Title Attack (>150 chars)',
    operation: 'create',
    path: 'products/prod_hack_2',
    data: { id: 'prod_hack_2', title: 'A'.repeat(160), price: 'R$ 99,90' },
    auth: { uid: 'admin_1', email: 'mackson.weiber13@gmail.com', emailVerified: true },
    expectedResult: 'PERMISSION_DENIED'
  },
  {
    name: '3. Unauthenticated Write (Guest deletes product)',
    operation: 'delete',
    path: 'products/prod_01',
    auth: null,
    expectedResult: 'PERMISSION_DENIED'
  },
  {
    name: '4. Unauthenticated Create (Guest creates product)',
    operation: 'create',
    path: 'products/prod_guest_1',
    data: { id: 'prod_guest_1', title: 'Perfume Falso', price: 'R$ 10,00' },
    auth: null,
    expectedResult: 'PERMISSION_DENIED'
  },
  {
    name: '5. Path Traversal / Invalid Doc ID Poisoning',
    operation: 'create',
    path: 'products/prod..hack@@',
    data: { id: 'prod..hack@@', title: 'Malicious', price: 'R$ 10,00' },
    auth: { uid: 'admin_1', email: 'mackson.weiber13@gmail.com', emailVerified: true },
    expectedResult: 'PERMISSION_DENIED'
  },
  {
    name: '6. Self-Admin Escalation by Regular User',
    operation: 'create',
    path: 'admins/attacker_uid',
    data: { email: 'attacker@gmail.com', role: 'superadmin' },
    auth: { uid: 'attacker_uid', email: 'attacker@gmail.com', emailVerified: true },
    expectedResult: 'PERMISSION_DENIED'
  },
  {
    name: '7. Spoofed Email Admin Bypass (email_verified is false)',
    operation: 'create',
    path: 'products/prod_spoof',
    data: { id: 'prod_spoof', title: 'Spoofed Admin Item', price: 'R$ 99,90' },
    auth: { uid: 'attacker_uid', email: 'mackson.weiber13@gmail.com', emailVerified: false },
    expectedResult: 'PERMISSION_DENIED'
  },
  {
    name: '8. Product Price Type Tampering (Number instead of string)',
    operation: 'create',
    path: 'products/prod_type_error',
    data: { id: 'prod_type_error', title: 'Valid Name', price: 199.90 },
    auth: { uid: 'admin_1', email: 'mackson.weiber13@gmail.com', emailVerified: true },
    expectedResult: 'PERMISSION_DENIED'
  },
  {
    name: '9. ID Mismatch Attack (path id != body id)',
    operation: 'create',
    path: 'products/prod_target',
    data: { id: 'prod_different', title: 'Valid Name', price: 'R$ 99,90' },
    auth: { uid: 'admin_1', email: 'mackson.weiber13@gmail.com', emailVerified: true },
    expectedResult: 'PERMISSION_DENIED'
  },
  {
    name: '10. Empty Required Fields (Missing price)',
    operation: 'create',
    path: 'products/prod_empty',
    data: { id: 'prod_empty', title: 'No Price' },
    auth: { uid: 'admin_1', email: 'mackson.weiber13@gmail.com', emailVerified: true },
    expectedResult: 'PERMISSION_DENIED'
  },
  {
    name: '11. Admin Document Deletion by Non-Admin',
    operation: 'delete',
    path: 'admins/superadmin_id',
    auth: { uid: 'regular_user_uid', email: 'user@gmail.com', emailVerified: true },
    expectedResult: 'PERMISSION_DENIED'
  },
  {
    name: '12. Direct Arbitrary Collection Write',
    operation: 'create',
    path: 'system_passwords/secret_doc',
    data: { secret: '123456' },
    auth: { uid: 'any_uid', email: 'user@gmail.com', emailVerified: true },
    expectedResult: 'PERMISSION_DENIED'
  }
];
