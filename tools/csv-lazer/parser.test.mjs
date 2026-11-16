import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
const inlineScripts = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi)];
assert.ok(inlineScripts.length > 0, 'CSV Lazer inline script was not found');

const context = vm.createContext({
    URL,
    Blob: class Blob {},
    Date,
    console,
    setTimeout,
    clearTimeout
});
vm.runInContext(inlineScripts.at(-1)[1], context, { filename: 'csv-lazer/index.html' });

const parse = input => JSON.parse(JSON.stringify(context.intelligentParse(input)));
const normalizeKey = key => context.normalizeKey(key);
const detectPlatform = link => context.detectPlatform(link);
const isExportAllowed = (rows, integrityErrors) => context.isExportAllowed(rows, integrityErrors);

const permutations = values => {
    if (values.length <= 1) return [values];
    return values.flatMap((value, index) =>
        permutations(values.filter((_, candidateIndex) => candidateIndex !== index))
            .map(rest => [value, ...rest])
    );
};

test('routes the screenshot bk-up-email format without overwriting account password', () => {
    const result = parse(`
https://instagram.com/synthetic_user

username: synthetic_user
password: account-secret
email: primary@example.test
email-password: primary-mail-secret
bk-up-email: recovery@example.test
password: recovery-secret
    `);

    assert.equal(result.accounts.length, 1);
    assert.deepEqual(result.accounts[0], {
        username: 'synthetic_user',
        password: 'account-secret',
        email: 'primary@example.test',
        email_password: 'primary-mail-secret',
        backup_email: 'recovery@example.test',
        backup_email_password: 'recovery-secret',
        profile_link: 'https://instagram.com/synthetic_user'
    });
    assert.equal(result.warnings.some(warning => warning.includes('W104')), false);
});

test('parses a seven-account bk-up-email batch without duplicate-key warnings', () => {
    const links = [];
    const blocks = [];

    for (let index = 1; index <= 7; index += 1) {
        links.push(`https://instagram.com/synthetic_user_${index}`);
        blocks.push([
            `username: synthetic_user_${index}`,
            `password: account-secret-${index}`,
            `email: primary${index}@example.test`,
            `email-password: primary-mail-secret-${index}`,
            `bk-up-email: recovery${index}@example.test`,
            `password: recovery-secret-${index}`
        ].join('\n'));
    }

    const result = parse(`${links.join('\n')}\n\n${blocks.join('\n\n')}`);

    assert.equal(result.accounts.length, 7);
    assert.equal(result.warnings.some(warning => warning.includes('W104')), false);
    result.accounts.forEach((account, index) => {
        const number = index + 1;
        assert.equal(account.password, `account-secret-${number}`);
        assert.equal(account.backup_email, `recovery${number}@example.test`);
        assert.equal(account.backup_email_password, `recovery-secret-${number}`);
    });
});

test('normalizes common backup and recovery email label variants', () => {
    const aliases = [
        'backup email',
        'backup-email',
        'backup_email',
        'backup mail',
        'back-up-email',
        'bk-up-email',
        'bk_up_email',
        'bk up mail',
        'bkup-email',
        'bkp_email',
        'recovery-email',
        'recovery_mail',
        'alternate-email',
        'alt_email'
    ];

    for (const label of aliases) {
        const result = parse(`username: user\npassword: account-secret\n${label}: recovery@example.test\npassword: recovery-secret`);
        assert.equal(result.accounts[0].password, 'account-secret', label);
        assert.equal(result.accounts[0].backup_email, 'recovery@example.test', label);
        assert.equal(result.accounts[0].backup_email_password, 'recovery-secret', label);
        assert.equal(result.warnings.some(warning => warning.includes('W104')), false, label);
    }
});

test('normalizes direct backup password label variants', () => {
    const aliases = [
        'backup-email-password',
        'backup_email_pass',
        'back-up-mail-password',
        'bk-up-email-password',
        'bkup_email_pass',
        'bkp-email-pass',
        'recovery-email-password',
        'recovery_mail_pass',
        'alternate-email-password',
        'alt_email_pass'
    ];

    for (const label of aliases) {
        assert.equal(normalizeKey(label), 'backup_email_password', label);
    }
});

test('preserves existing secondary-email contextual password routing', () => {
    const result = parse(`
username => user
password => account-secret
sec-email => secondary@example.test
password => secondary-secret
    `);

    assert.equal(result.accounts[0].password, 'account-secret');
    assert.equal(result.accounts[0].secondary_email, 'secondary@example.test');
    assert.equal(result.accounts[0].secondary_email_password, 'secondary-secret');
});

test('preserves primary email-password and unknown custom columns', () => {
    const result = parse(`
login | user
pass | account-secret
e-mail | primary@example.test
email_pass | mail-secret
seller-note | preserve me
    `);

    assert.equal(result.accounts[0].username, 'user');
    assert.equal(result.accounts[0].password, 'account-secret');
    assert.equal(result.accounts[0].email, 'primary@example.test');
    assert.equal(result.accounts[0].email_password, 'mail-secret');
    assert.equal(result.accounts[0].seller_note, 'preserve me');
});

test('keeps password-like values intact when they contain separators', () => {
    const result = parse(`username: user\npassword: left:right=middle|right\nbackup-email: recovery@example.test\npassword: backup::secret=>value`);

    assert.equal(result.accounts[0].password, 'left:right=middle|right');
    assert.equal(result.accounts[0].backup_email_password, 'backup::secret=>value');
});

test('retains unlabelled block detection and confirmation signal', () => {
    const result = parse(`@synthetic_user\naccount-secret\nprimary@example.test\nmail-secret\nNigeria`);

    assert.equal(result.autoDetectedCount, 1);
    assert.equal(result.accounts[0].username, '@synthetic_user');
    assert.equal(result.accounts[0].password, 'account-secret');
    assert.equal(result.accounts[0].email, 'primary@example.test');
    assert.equal(result.accounts[0].email_password, 'mail-secret');
    assert.equal(result.accounts[0].country, 'Nigeria');
});

test('matches multiple profile links to their credential blocks by identity', () => {
    const result = parse(`
https://instagram.com/second_user
https://instagram.com/first_user

username: first_user
password: first-secret

username: second_user
password: second-secret
    `);

    assert.equal(result.accounts.length, 2);
    assert.equal(result.accounts[0].profile_link, 'https://instagram.com/first_user');
    assert.equal(result.accounts[1].profile_link, 'https://instagram.com/second_user');
    assert.deepEqual(result.integrityErrors, []);
});

test('reserves exact identity matches before handling unrelated blocks', () => {
    const result = parse(`
https://x.com/profile_alpha
https://x.com/profile_beta

username: unrelated_account
password: sample-one

username: profile_alpha
password: sample-two
    `);

    assert.equal(result.accounts[0].username, 'unrelated_account');
    assert.equal(result.accounts[0].profile_link, '');
    assert.equal(result.accounts[1].username, 'profile_alpha');
    assert.equal(result.accounts[1].profile_link, 'https://x.com/profile_alpha');
    assert.equal(result.accounts.some(account =>
        account.username === 'profile_alpha' && account.profile_link === 'https://x.com/profile_beta'
    ), false);
    assert.equal(result.integrityErrors.some(error => error.startsWith('E203:')), true);
    assert.equal(result.integrityErrors.some(error => error.startsWith('E204:')), true);
});

test('matches every permutation of standalone links and credential blocks deterministically', () => {
    const identities = ['user_a1', 'user_b2', 'user_c3', 'user_d4'];

    for (const linkOrder of permutations(identities)) {
        for (const blockOrder of permutations(identities)) {
            const links = linkOrder.map(identity => `https://x.com/${identity}`).join('\n');
            const blocks = blockOrder.map(identity =>
                `username: ${identity}\npassword: secret-${identity}`
            ).join('\n\n');
            const result = parse(`${links}\n\n${blocks}`);

            assert.deepEqual(result.integrityErrors, [], `${linkOrder.join(',')} / ${blockOrder.join(',')}`);
            assert.equal(result.accounts.length, identities.length);
            result.accounts.forEach(account => {
                assert.equal(account.profile_link, `https://x.com/${account.username}`);
            });
        }
    }
});

test('blocks a profile link that matches duplicate credential identities', () => {
    const result = parse(`
https://x.com/repeated_user

username: repeated_user
password: sample-one

username: repeated_user
password: sample-two
    `);

    assert.equal(result.integrityErrors.some(error => error.startsWith('E202:')), true);
    assert.equal(result.accounts.filter(account => account.username === 'repeated_user').every(account => account.profile_link === ''), true);
});

test('blocks duplicate profile URLs even when their trailing slash differs', () => {
    const result = parse(`
https://x.com/duplicate_user
https://x.com/duplicate_user/

username: duplicate_user
password: sample-secret
    `);

    assert.equal(result.integrityErrors.some(error => error.startsWith('E201:')), true);
    assert.equal(result.integrityErrors.some(error => error.startsWith('E205:')), true);
});

test('preserves explicitly labelled profile links without positional inference', () => {
    const result = parse(`
username: first_account
password: sample-one
profile_link: https://x.com/explicit_first

username: second_account
password: sample-two
profile: https://x.com/explicit_second
    `);

    assert.deepEqual(result.integrityErrors, []);
    assert.equal(result.accounts[0].profile_link, 'https://x.com/explicit_first');
    assert.equal(result.accounts[1].profile_link, 'https://x.com/explicit_second');
});

test('keeps profile links optional when no standalone profile list was supplied', () => {
    const result = parse(`username: account_without_link\npassword: sample-secret`);

    assert.deepEqual(result.integrityErrors, []);
    assert.equal(result.accounts[0].profile_link, '');
    assert.equal(result.warnings.some(warning => warning.startsWith('W110:')), true);
});

test('uses username as the authoritative identity when username and email disagree', () => {
    const result = parse(`
https://x.com/email_identity

username: different_username
email: email_identity@example.test
password: sample-secret
    `);

    assert.equal(result.accounts[0].profile_link, '');
    assert.equal(result.integrityErrors.some(error => error.startsWith('E203:')), true);
});

test('extracts only the canonical identity segment for every supported profile platform', () => {
    const cases = [
        ['https://x.com/sample_x', 'sample_x'],
        ['https://instagram.com/sample_ig/', 'sample_ig'],
        ['https://www.tiktok.com/@sample_tt', 'sample_tt'],
        ['https://facebook.com/sample_fb', 'sample_fb'],
        ['https://linkedin.com/in/sample_li', 'sample_li'],
        ['https://reddit.com/user/sample_reddit', 'sample_reddit'],
        ['https://youtube.com/@sample_yt', 'sample_yt']
    ];

    for (const [link, username] of cases) {
        const result = parse(`${link}\n\nusername: ${username}\npassword: sample-secret`);
        assert.deepEqual(result.integrityErrors, [], link);
        assert.equal(result.accounts[0].profile_link, link, link);
    }
});

test('does not treat reserved route words as profile identities', () => {
    const result = parse(`
https://x.com/i/user/12345

username: user
password: sample-secret
    `);

    assert.equal(result.accounts[0].profile_link, '');
    assert.equal(result.integrityErrors.some(error => error.startsWith('E203:')), true);
});

test('requires exact supported hostnames instead of substring domain matches', () => {
    assert.equal(detectPlatform('https://x.com/sample'), 'twitter');
    assert.equal(detectPlatform('https://mobile.twitter.com/sample'), 'twitter');
    assert.equal(detectPlatform('https://notx.com/sample'), null);
    assert.equal(detectPlatform('https://instagram.com.evil.test/sample'), null);
    assert.equal(detectPlatform('https://fakeyoutube.com/sample'), null);
});

test('detects the same explicit profile identity across x.com and twitter.com URLs', () => {
    const result = parse(`
username: first
profile_link: https://x.com/shared_identity?s=20

username: second
profile_link: https://twitter.com/shared_identity/
    `);

    assert.equal(result.integrityErrors.some(error => error.startsWith('E205:')), true);
});

test('export policy fails closed whenever an integrity error exists', () => {
    assert.equal(isExportAllowed([{ username: 'safe_row' }], []), true);
    assert.equal(isExportAllowed([{ username: 'blocked_row' }], ['E203: mismatch']), false);
    assert.equal(isExportAllowed([], []), false);
});

test('keeps an internal 2FA tool URL separate from reordered X profile links', () => {
    const result = parse(`
https://x.com/profile_north
https://x.com/profile_south

username: profile_south
password: sample-south
2fa_link: https://fastaccs.com/tools/easylogin/sample-south

username: profile_north
password: sample-north
2fa_link: https://fastaccs.com/tools/easylogin/sample-north
    `);

    assert.deepEqual(result.integrityErrors, []);
    assert.equal(result.accounts[0].profile_link, 'https://x.com/profile_south');
    assert.equal(result.accounts[0]['2fa_link'], 'https://fastaccs.com/tools/easylogin/sample-south');
    assert.equal(result.accounts[1].profile_link, 'https://x.com/profile_north');
    assert.equal(result.accounts[1]['2fa_link'], 'https://fastaccs.com/tools/easylogin/sample-north');
});
