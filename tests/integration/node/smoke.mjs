// Node smoke: register, init, log.info (sys), emit (audit) with PII detail.
import fasten, { register, init, emit, log } from 'fasten';

register('user', {
    USER_CREATED: {
        id: 'USER_CREATED', domain: 'user', category: 'account',
        action: 'create', severity: 'info',
        description: 'New user account created', emitter: 'auth-service',
    },
});

process.env.FASTEN_SERVICE_ID = 'itest-node';
process.env.FASTEN_NODE_ID = 'host-itest';
init();

// 1. sys row
log.info('startup_ok', { lang: 'node' });

// 2. audit row with PII detail
emit({
    code: 'USER_CREATED',
    target: 'u-42',
    actor: 'admin',
    actorKind: 'user',
    detail: {
        email: 'alice@acme.com',
        api_key: 'sk-secret-abc',
        customer_token: 'tok-substring-test', // substring match on 'token'
        nested: { token: 'xyz', preserved: 'ok' },
    },
});
