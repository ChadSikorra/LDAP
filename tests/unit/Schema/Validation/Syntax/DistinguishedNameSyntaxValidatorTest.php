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

use FreeDSx\Ldap\Schema\Validation\Syntax\DistinguishedNameSyntaxValidator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class DistinguishedNameSyntaxValidatorTest extends TestCase
{
    private DistinguishedNameSyntaxValidator $subject;

    protected function setUp(): void
    {
        $this->subject = new DistinguishedNameSyntaxValidator();
    }

    #[DataProvider('validValuesProvider')]
    public function test_it_accepts_valid_distinguished_names(string $value): void
    {
        self::assertTrue($this->subject->isValid($value));
    }

    #[DataProvider('invalidValuesProvider')]
    public function test_it_rejects_invalid_distinguished_names(string $value): void
    {
        self::assertFalse($this->subject->isValid($value));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function validValuesProvider(): array
    {
        return [
            'multi rdn' => ['cn=Alice,dc=example,dc=com'],
            'single rdn' => ['dc=example'],
            'multivalued rdn' => ['cn=Alice+sn=Smith,dc=example'],
            'empty is the root dse dn' => [''],
        ];
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidValuesProvider(): array
    {
        return [
            'free text' => ['not a dn'],
            'no assertion' => ['foo'],
            'trailing rdn without value' => ['cn=Alice,com'],
        ];
    }
}
