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
});
