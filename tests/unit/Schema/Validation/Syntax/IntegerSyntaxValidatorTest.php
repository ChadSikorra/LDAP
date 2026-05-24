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

use FreeDSx\Ldap\Schema\Validation\Syntax\IntegerSyntaxValidator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class IntegerSyntaxValidatorTest extends TestCase
{
    private IntegerSyntaxValidator $subject;

    protected function setUp(): void
    {
        $this->subject = new IntegerSyntaxValidator();
    }

    #[DataProvider('validValuesProvider')]
    public function test_it_accepts_valid_integers(string $value): void
    {
        self::assertTrue($this->subject->isValid($value));
    }

    #[DataProvider('invalidValuesProvider')]
    public function test_it_rejects_invalid_integers(string $value): void
    {
        self::assertFalse($this->subject->isValid($value));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function validValuesProvider(): array
    {
        return [
            'zero' => ['0'],
            'positive' => ['42'],
            'negative' => ['-42'],
            'arbitrary precision' => ['123456789012345678901234567890'],
        ];
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidValuesProvider(): array
    {
        return [
            'empty' => [''],
            'alpha' => ['abc'],
            'leading zero' => ['007'],
            'negative zero' => ['-0'],
            'decimal' => ['1.5'],
            'plus sign' => ['+5'],
            'space between sign and digits' => ['- 5'],
            'leading space' => [' 5'],
            'trailing space' => ['5 '],
            'trailing text' => ['12abc'],
        ];
    }
}
