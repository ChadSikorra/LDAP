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

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\DigestMD5MechanismOptionsBuilder;
use FreeDSx\Ldap\Protocol\Bind\Sasl\UsernameExtractor\SaslUsernameExtractorInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Options\DigestMD5Options;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class DigestMD5MechanismOptionsBuilderTest extends TestCase
{
    private PasswordAuthenticatableInterface&MockObject $mockHandler;

    private SaslUsernameExtractorInterface&MockObject $mockUsernameExtractor;

    private DigestMD5MechanismOptionsBuilder $subject;

    protected function setUp(): void
    {
        $this->mockHandler = $this->createMock(PasswordAuthenticatableInterface::class);
        $this->mockUsernameExtractor = $this->createMock(SaslUsernameExtractorInterface::class);

        $this->subject = new DigestMD5MechanismOptionsBuilder(
            $this->mockHandler,
            $this->mockUsernameExtractor,
        );
    }

    public function test_it_returns_null_when_no_bytes_received(): void
    {
        self::assertNull($this->subject->buildOptions(null, MechanismName::DIGEST_MD5));
    }

    public function test_it_builds_options_with_the_password_when_bytes_are_received(): void
    {
        $this->mockUsernameExtractor
            ->method('extractUsername')
            ->with(MechanismName::DIGEST_MD5, 'client-response')
            ->willReturn('cn=user,dc=foo,dc=bar');

        $this->mockHandler
            ->method('getPassword')
            ->with('cn=user,dc=foo,dc=bar', MechanismName::DIGEST_MD5->value)
            ->willReturn('12345');

        $options = $this->subject->buildOptions('client-response', MechanismName::DIGEST_MD5);

        self::assertInstanceOf(DigestMD5Options::class, $options);
        self::assertSame('12345', $options->getPassword());
    }

    public function test_it_throws_invalid_credentials_when_password_is_not_found(): void
    {
        $this->mockUsernameExtractor
            ->method('extractUsername')
            ->willReturn('unknown-user');

        $this->mockHandler
            ->method('getPassword')
            ->willReturn(null);

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::INVALID_CREDENTIALS);

        $this->subject->buildOptions('client-response', MechanismName::DIGEST_MD5);
    }
}
