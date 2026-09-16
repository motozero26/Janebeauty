# Security Specification & Threat Model — JANY BEAUTY

## 1. Data Invariants
1. **Catalog Integrity**: Any product in `/products/{productId}` must have a non-empty `id`, `title`, and `price`. Document ID must match `data.id` and pass `isValidId()`.
2. **Field Boundaries**: String lengths are strictly capped (`title` <= 150, `price` <= 60, `description` <= 1000, `tag` <= 60, `rating` <= 120, `image` <= 500000, `alt` <= 200, `whatsapp` <= 500, `buyLink` <= 500).
3. **No Shadow Fields**: Strict schema checks prevent injection of unexpected keys.
4. **Zero-Trust Access Control**: Public users have read access (`get`, `list`) to `/products/{productId}` so visitors can browse the store. Write operations (`create`, `update`, `delete`) require authenticated administrator identity.
5. **Privilege Integrity**: `/admins/{adminId}` can only be read/modified by verified administrators. Users cannot self-escalate to admin.
6. **Connection Test**: `/test/{docId}` permits read for initial connectivity verification.

---

## 2. The "Dirty Dozen" Malicious Payloads

1. **Payload 1 (Shadow Field Injection)**: Creating a product with extra unauthorized field `isFree: true`.
2. **Payload 2 (Oversized Title Attack / Denial of Wallet)**: Submitting a product title with 10,000 characters.
3. **Payload 3 (Unauthenticated Write)**: An unauthenticated guest attempting to DELETE a product.
4. **Payload 4 (Unauthenticated Create)**: An unauthenticated guest trying to POST a fake product.
5. **Payload 5 (Path Traversal / ID Poisoning)**: Document ID containing `../admin/hack` or special characters.
6. **Payload 6 (Self-Admin Escalation)**: Regular user writing `{ email: "attacker@test.com", role: "superadmin" }` into `/admins/attackerUid`.
7. **Payload 7 (Spoofed Email Admin Bypass)**: User presenting unverified email claiming to be an admin.
8. **Payload 8 (Product Price Type Tampering)**: Submitting `price: 123.45` as a number instead of string schema.
9. **Payload 9 (ID Mismatch Attack)**: Submitting document to `/products/prod_123` with payload `{ id: "prod_456" }`.
10. **Payload 10 (Empty Required Fields)**: Submitting `{ id: "prod_1", title: "" }` missing price and with empty title.
11. **Payload 11 (Admin Document Deletion)**: Non-admin trying to wipe the `/admins` collection.
12. **Payload 12 (Direct Arbitrary Collection Write)**: Writing to non-whitelisted paths like `/passwords` or `/orders_backup`.
