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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder;

use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\PlainMechanismOptionsBuilder;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Options\PlainOptions;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class PlainMechanismOptionsBuilderTest extends TestCase
{
    private PasswordAuthenticatableInterface&MockObject $mockAuthenticator;

    private PlainMechanismOptionsBuilder $subject;

    protected function setUp(): void
    {
        $this->mockAuthenticator = $this->createMock(PasswordAuthenticatableInterface::class);
        $this->subject = new PlainMechanismOptionsBuilder($this->mockAuthenticator);
    }

    public function test_it_builds_options_with_a_validate_callable(): void
    {
        $options = $this->subject->buildOptions(null, MechanismName::PLAIN);

        self::assertInstanceOf(PlainOptions::class, $options);
        self::assertIsCallable($options->getValidate());
    }

    public function test_the_validate_callable_delegates_to_backend_verify_password(): void
    {
        $this->mockAuthenticator
            ->expects(self::once())
            ->method('verifyPassword')
            ->with('cn=user,dc=foo,dc=bar', '12345')
            ->willReturn(true);

        $options = $this->subject->buildOptions(null, MechanismName::PLAIN);
        self::assertInstanceOf(PlainOptions::class, $options);
        $validate = $options->getValidate();
        assert(is_callable($validate));
        $result = $validate('authzid', 'cn=user,dc=foo,dc=bar', '12345');

        self::assertTrue($result);
    }

    public function test_the_validate_callable_returns_false_when_verify_password_fails(): void
    {
        $this->mockAuthenticator
            ->method('verifyPassword')
            ->willReturn(false);

        $options = $this->subject->buildOptions(null, MechanismName::PLAIN);
        self::assertInstanceOf(PlainOptions::class, $options);
        $validate = $options->getValidate();
        assert(is_callable($validate));
        $result = $validate(null, 'user', 'wrong');

        self::assertFalse($result);
    }

    public function test_it_builds_the_same_options_regardless_of_received_bytes(): void
    {
        $optionsWithNull = $this->subject->buildOptions(null, MechanismName::PLAIN);
        $optionsWithBytes = $this->subject->buildOptions('some-bytes', MechanismName::PLAIN);

        self::assertInstanceOf(PlainOptions::class, $optionsWithNull);
        self::assertInstanceOf(PlainOptions::class, $optionsWithBytes);
    }
}
