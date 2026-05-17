<?php

declare(strict_types=1);

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Auth;

use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashVerifier;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PasswordHashVerifierTest extends TestCase
{
    private PasswordHashVerifier $subject;

    protected function setUp(): void
    {
        $this->subject = new PasswordHashVerifier();
    }

    public function test_plaintext_verifies_when_equal(): void
    {
        self::assertTrue($this->subject->verify('secret', 'secret'));
    }

    public function test_plaintext_does_not_verify_when_different(): void
    {
        self::assertFalse($this->subject->verify('secret', 'other'));
    }

    public function test_sha_format_verifies(): void
    {
        $hashed = '{SHA}' . base64_encode(sha1('mypassword', true));

        self::assertTrue($this->subject->verify('mypassword', $hashed));
    }

    public function test_ssha_format_verifies(): void
    {
        $salt = random_bytes(8);
        $hashed = '{SSHA}' . base64_encode(sha1('mypassword' . $salt, true) . $salt);

        self::assertTrue($this->subject->verify('mypassword', $hashed));
    }

    public function test_md5_format_verifies(): void
    {
        $hashed = '{MD5}' . base64_encode(md5('mypassword', true));

        self::assertTrue($this->subject->verify('mypassword', $hashed));
    }

    public function test_smd5_format_verifies(): void
    {
        $salt = random_bytes(8);
        $hashed = '{SMD5}' . base64_encode(md5('mypassword' . $salt, true) . $salt);

        self::assertTrue($this->subject->verify('mypassword', $hashed));
    }

    public function test_bcrypt_format_verifies(): void
    {
        $hashed = '{BCRYPT}' . password_hash('mypassword', PASSWORD_BCRYPT);

        self::assertTrue($this->subject->verify('mypassword', $hashed));
    }

    public function test_argon2_format_verifies(): void
    {
        $hashed = '{ARGON2}' . password_hash('mypassword', PASSWORD_ARGON2ID);

        self::assertTrue($this->subject->verify('mypassword', $hashed));
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function hashedPrefixProvider(): array
    {
        return [
            '{SHA}'    => ['{SHA}' . base64_encode(sha1('mypassword', true))],
            '{MD5}'    => ['{MD5}' . base64_encode(md5('mypassword', true))],
            '{BCRYPT}' => ['{BCRYPT}' . password_hash('mypassword', PASSWORD_BCRYPT)],
            '{ARGON2}' => ['{ARGON2}' . password_hash('mypassword', PASSWORD_ARGON2ID)],
        ];
    }

    #[DataProvider('hashedPrefixProvider')]
    public function test_wrong_password_does_not_verify(string $hashed): void
    {
        self::assertFalse($this->subject->verify('wrong', $hashed));
    }
}
