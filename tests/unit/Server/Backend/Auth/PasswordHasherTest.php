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
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashScheme;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashVerifier;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PasswordHasherTest extends TestCase
{
    public function test_default_scheme_is_bcrypt(): void
    {
        $hashed = (new PasswordHasher())->hash('secret');

        self::assertStringStartsWith(
            '{BCRYPT}',
            $hashed,
        );
    }

    /**
     * @return array<string, array{0: PasswordHashScheme, 1: non-empty-string}>
     */
    public static function schemeProvider(): array
    {
        return [
            'ssha' => [PasswordHashScheme::Ssha, '{SSHA}'],
            'bcrypt' => [PasswordHashScheme::Bcrypt, '{BCRYPT}'],
            'argon2' => [PasswordHashScheme::Argon2, '{ARGON2}'],
        ];
    }

    /**
     * @param non-empty-string $expectedPrefix
     */
    #[DataProvider('schemeProvider')]
    public function test_each_scheme_produces_its_prefix(
        PasswordHashScheme $scheme,
        string $expectedPrefix,
    ): void {
        $hashed = (new PasswordHasher($scheme))->hash('secret');

        self::assertStringStartsWith(
            $expectedPrefix,
            $hashed,
        );
    }

    #[DataProvider('schemeProvider')]
    public function test_each_scheme_round_trips_through_verifier(
        PasswordHashScheme $scheme,
    ): void {
        $hashed = (new PasswordHasher($scheme))->hash('mypassword');

        self::assertTrue(
            (new PasswordHashVerifier())->verify('mypassword', $hashed),
        );
    }

    #[DataProvider('schemeProvider')]
    public function test_wrong_password_does_not_verify(
        PasswordHashScheme $scheme,
    ): void {
        $hashed = (new PasswordHasher($scheme))->hash('mypassword');

        self::assertFalse(
            (new PasswordHashVerifier())->verify('wrong', $hashed),
        );
    }

    #[DataProvider('schemeProvider')]
    public function test_two_hashes_of_same_input_differ_due_to_random_salt(
        PasswordHashScheme $scheme,
    ): void {
        $hasher = new PasswordHasher($scheme);
        $first = $hasher->hash('password');
        $second = $hasher->hash('password');

        self::assertNotSame(
            $first,
            $second,
        );
    }

    public function test_generate_returns_16_character_string(): void
    {
        self::assertSame(
            16,
            strlen((new PasswordHasher())->generate()),
        );
    }

    public function test_generate_produces_different_values_on_each_call(): void
    {
        $hasher = new PasswordHasher();

        self::assertNotSame(
            $hasher->generate(),
            $hasher->generate(),
        );
    }
}
