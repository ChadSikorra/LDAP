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

namespace Tests\Unit\FreeDSx\Ldap\Schema\Validation\Syntax;

use FreeDSx\Ldap\Schema\Validation\Syntax\Ia5StringSyntaxValidator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class Ia5StringSyntaxValidatorTest extends TestCase
{
    private Ia5StringSyntaxValidator $subject;

    protected function setUp(): void
    {
        $this->subject = new Ia5StringSyntaxValidator();
    }

    #[DataProvider('validValuesProvider')]
    public function test_it_accepts_ascii_only_values(string $value): void
    {
        self::assertTrue($this->subject->isValid($value));
    }

    #[DataProvider('invalidValuesProvider')]
    public function test_it_rejects_non_ascii_values(string $value): void
    {
        self::assertFalse($this->subject->isValid($value));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function validValuesProvider(): array
    {
        return [
            'email' => ['user@example.com'],
            'ascii punctuation' => ['plain ascii !@#$%^&*()'],
            'empty is permitted' => [''],
        ];
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidValuesProvider(): array
    {
        return [
            'accented letter' => ['café'],
            'diaeresis' => ['naïve'],
            'emoji' => ['hello 😀'],
        ];
    }
}
