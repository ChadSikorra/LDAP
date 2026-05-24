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

use FreeDSx\Ldap\Schema\Validation\Syntax\BooleanSyntaxValidator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class BooleanSyntaxValidatorTest extends TestCase
{
    private BooleanSyntaxValidator $subject;

    protected function setUp(): void
    {
        $this->subject = new BooleanSyntaxValidator();
    }

    #[DataProvider('validValuesProvider')]
    public function test_it_accepts_the_exact_boolean_literals(string $value): void
    {
        self::assertTrue($this->subject->isValid($value));
    }

    #[DataProvider('invalidValuesProvider')]
    public function test_it_rejects_anything_else(string $value): void
    {
        self::assertFalse($this->subject->isValid($value));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function validValuesProvider(): array
    {
        return [
            'true' => ['TRUE'],
            'false' => ['FALSE'],
        ];
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidValuesProvider(): array
    {
        return [
            'empty' => [''],
            'lowercase true' => ['true'],
            'mixed case false' => ['False'],
            'yes' => ['yes'],
            'numeric one' => ['1'],
            'numeric zero' => ['0'],
            'trailing space' => ['TRUE '],
        ];
    }
}
