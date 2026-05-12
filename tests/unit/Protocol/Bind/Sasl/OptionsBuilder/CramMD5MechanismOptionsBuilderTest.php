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

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\CramMD5MechanismOptionsBuilder;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\Auth\SaslIdentity;
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Options\CramMD5Options;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class CramMD5MechanismOptionsBuilderTest extends TestCase
{
    private PasswordAuthenticatableInterface&MockObject $mockHandler;

    private CramMD5MechanismOptionsBuilder $subject;

    protected function setUp(): void
    {
        $this->mockHandler = $this->createMock(PasswordAuthenticatableInterface::class);
        $this->subject = new CramMD5MechanismOptionsBuilder($this->mockHandler);
    }

    public function test_it_returns_null_when_no_bytes_received(): void
    {
        self::assertNull($this->subject->buildOptions(null, MechanismName::CRAM_MD5));
    }

    public function test_it_builds_options_with_a_password_callable_when_bytes_are_received(): void
    {
        $options = $this->subject->buildOptions(
            'some-client-response',
            MechanismName::CRAM_MD5,
        );

        self::assertInstanceOf(CramMD5Options::class, $options);
        self::assertIsCallable($options->getPasswordCallback());
    }

    public function test_the_password_callable_returns_an_hmac_of_the_challenge(): void
    {
        $identity = new SaslIdentity(
            '12345',
            new Dn('cn=user,dc=foo,dc=bar'),
        );

        $this->mockHandler
            ->method('getSaslIdentity')
            ->with('cn=user,dc=foo,dc=bar', MechanismName::CRAM_MD5)
            ->willReturn($identity);

        $options = $this->subject->buildOptions('some-bytes', MechanismName::CRAM_MD5);
        self::assertInstanceOf(CramMD5Options::class, $options);
        $callback = $options->getPasswordCallback();
        assert(is_callable($callback));
        // The challenge passed to the callable is the encoded challenge string exactly as the
        // client received it (e.g. "<nonce>"), per RFC 2195.
        $challenge = '<challenge@example.com>';
        $result = $callback('cn=user,dc=foo,dc=bar', $challenge);

        self::assertSame(
            hash_hmac('md5', '<challenge@example.com>', '12345'),
            $result,
        );
    }

    public function test_the_password_callable_throws_invalid_credentials_when_user_not_found(): void
    {
        $this->mockHandler
            ->method('getSaslIdentity')
            ->willReturn(null);

        $options = $this->subject->buildOptions(
            'some-bytes',
            MechanismName::CRAM_MD5,
        );
        self::assertInstanceOf(CramMD5Options::class, $options);
        $callback = $options->getPasswordCallback();
        assert(is_callable($callback));

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::INVALID_CREDENTIALS);

        $callback('unknown-user', 'challenge');
    }

    public function test_get_resolved_dn_is_populated_after_successful_callback(): void
    {
        $identity = new SaslIdentity(
            '12345',
            new Dn('cn=user,dc=foo,dc=bar'),
        );

        $this->mockHandler
            ->method('getSaslIdentity')
            ->willReturn($identity);

        $options = $this->subject->buildOptions('some-bytes', MechanismName::CRAM_MD5);
        assert($options instanceof CramMD5Options);
        $callback = $options->getPasswordCallback();
        assert(is_callable($callback));
        $callback('cn=user,dc=foo,dc=bar', '<challenge@example.com>');

        self::assertSame(
            'cn=user,dc=foo,dc=bar',
            $this->subject->getResolvedDn()?->toString(),
        );
    }
}
