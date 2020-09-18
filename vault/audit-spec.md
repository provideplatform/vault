## Auditing in Provide Vault

Purpose of the audit log is to enable the tracking of every interaction with the vault.

The audit log will track:

* IP Address of requestor
* RequestId of request (might need to be generated inside handler?)
* Host of vault application (environment variable?)
* Requestor UserId (if provided in token)
* Requestor ApplicationId (if provided in token)
* Requestor OrganizationId (if provided in token)
* Request path/operation
* Request data (all sensitive data to be hashed - i.e. unsealer key, secrets etc.) **UPDATE this when coding**
* Response data (all sensitive data to be hashed - i.e. unsealer key, secrets etc.) **UPDATE this when coding**


Everything to be wrapped in an /admin/ path - this will be protected by JWT token, but TBD what permissions are required to access this path.  As currently functionality will be limited to generating a new unsealer key and initialising the audit logging, it's low-impact as regarding locking down this path via an API gateway or similar, although once this feature is extended to configure the output path of the audit logs (we'll begin with fixing audit logs to a physical file which can be picked up by a log aggregator)

# Audit Log Output

Initially, the audit log will be initially fixed to STDOUT.  Next step is to log to a file.  This file will have a fixed format (vault-audit.log) initially, although future iterations can look at log rotations.

# Audit Log Format
JSON format logs - for easy parsing by an external log processor

# Context

We'll use the context object, passing it down into the functions one level below the handlers.  This context will have the logging information needed (and it will cope with nil contexts).  Function parameter information and response information will be added to the context and the audit logger will trip at the start of the function and the end, logging the response information passed as well.

# Standard Logging
It might be better to hash all strings as standard.  Need to review the code in detail, as there's public keys output as hex strings, but it's pretty vital that nothing sensitive gets leaked in the audit logs.  Might need a few logging methods linked to the function call (sign/verify/encrypt/decrypt/create/delete/list/secrets/unseal/createseal), but it would be nice for this to have a standard operating method so the audit doesn't have to be updated if new request/response fields are added to the handlers.







