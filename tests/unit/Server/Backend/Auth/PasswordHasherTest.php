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

use FreeDSx\Ldap\Server\Backend\Auth\PasswordHasher;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashVerifier;
use PHPUnit\Framework\TestCase;

final class PasswordHasherTest extends TestCase
{
    private PasswordHasher $subject;

    protected function setUp(): void
    {
        $this->subject = new PasswordHasher();
    }

    public function test_hash_produces_ssha_string(): void
    {
        $hashed = $this->subject->hash('secret');

        self::assertStringStartsWith(
            '{SSHA}',
            $hashed,
        );
    }

    public function test_hash_is_verified_by_password_hash_verifier(): void
    {
        $hashed = $this->subject->hash('mypassword');

        self::assertTrue(
            (new PasswordHashVerifier())->verify('mypassword', $hashed),
        );
    }

    public function test_wrong_password_does_not_verify(): void
    {
        $hashed = $this->subject->hash('mypassword');

        self::assertFalse(
            (new PasswordHashVerifier())->verify('wrong', $hashed),
        );
    }

    public function test_two_hashes_of_same_input_differ_due_to_random_salt(): void
    {
        $first = $this->subject->hash('password');
        $second = $this->subject->hash('password');

        self::assertNotSame(
            $first,
            $second,
        );
    }

    public function test_generate_returns_16_character_string(): void
    {
        $generated = $this->subject->generate();

        self::assertSame(
            16,
            strlen($generated),
        );
    }

    public function test_generate_produces_different_values_on_each_call(): void
    {
        $first = $this->subject->generate();
        $second = $this->subject->generate();

        self::assertNotSame(
            $first,
            $second,
        );
    }
}
