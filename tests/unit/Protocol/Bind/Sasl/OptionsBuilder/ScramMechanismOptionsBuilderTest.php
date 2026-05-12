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
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\ScramMechanismOptionsBuilder;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\Auth\SaslIdentity;
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Options\ScramOptions;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ScramMechanismOptionsBuilderTest extends TestCase
{
    private PasswordAuthenticatableInterface&MockObject $mockHandler;

    private ScramMechanismOptionsBuilder $subject;

    protected function setUp(): void
    {
        $this->mockHandler = $this->createMock(PasswordAuthenticatableInterface::class);
        $this->subject = new ScramMechanismOptionsBuilder($this->mockHandler);
    }

    public function test_it_returns_null_when_no_bytes_received(): void
    {
        self::assertNull($this->subject->buildOptions(null, MechanismName::SCRAM_SHA256));
    }

    public function test_it_returns_null_for_client_first_message(): void
    {
        // Client-first: GS2 header + username + cnonce, no proof field.
        $clientFirst = 'n,,n=testuser,r=clientnonce123';

        self::assertNull($this->subject->buildOptions($clientFirst, MechanismName::SCRAM_SHA256));
    }

    public function test_it_extracts_username_from_client_first_and_provides_password_on_client_final(): void
    {
        $identity = new SaslIdentity('secret', new Dn('cn=testuser,dc=example,dc=com'));

        $this->mockHandler
            ->expects(self::once())
            ->method('getSaslIdentity')
            ->with('testuser', MechanismName::SCRAM_SHA256)
            ->willReturn($identity);

        $this->subject->buildOptions('n,,n=testuser,r=clientnonce123', MechanismName::SCRAM_SHA256);
        $options = $this->subject->buildOptions('c=biws,r=clientnonce123servernonce,p=dGVzdA==', MechanismName::SCRAM_SHA256);

        self::assertInstanceOf(ScramOptions::class, $options);
        self::assertSame('secret', $options->getPassword());
    }

    public function test_it_passes_the_mechanism_name_to_the_handler(): void
    {
        $identity = new SaslIdentity('pw', new Dn('cn=user,dc=example,dc=com'));

        $this->mockHandler
            ->expects(self::once())
            ->method('getSaslIdentity')
            ->with('user', MechanismName::SCRAM_SHA512)
            ->willReturn($identity);

        $this->subject->buildOptions('n,,n=user,r=nonce', MechanismName::SCRAM_SHA512);
        $this->subject->buildOptions('c=biws,r=fullnonce,p=proof==', MechanismName::SCRAM_SHA512);
    }

    public function test_it_throws_invalid_credentials_when_user_not_found(): void
    {
        $this->mockHandler
            ->method('getSaslIdentity')
            ->willReturn(null);

        $this->subject->buildOptions('n,,n=unknown,r=nonce', MechanismName::SCRAM_SHA256);

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::INVALID_CREDENTIALS);

        $this->subject->buildOptions('c=biws,r=fullnonce,p=someproof==', MechanismName::SCRAM_SHA256);
    }

    public function test_it_throws_protocol_error_when_client_final_received_before_client_first(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::PROTOCOL_ERROR);

        // Client-final arrives without a prior client-first.
        $this->subject->buildOptions('c=biws,r=fullnonce,p=proof==', MechanismName::SCRAM_SHA256);
    }

    public function test_it_decodes_rfc5802_encoded_username(): void
    {
        $identity = new SaslIdentity('pw', new Dn('cn=user,dc=example,dc=com'));

        $this->mockHandler
            ->expects(self::once())
            ->method('getSaslIdentity')
            ->with('user,name=test', MechanismName::SCRAM_SHA256)
            ->willReturn($identity);

        // ',' encoded as '=2C', '=' encoded as '=3D'
        $this->subject->buildOptions('n,,n=user=2Cname=3Dtest,r=nonce', MechanismName::SCRAM_SHA256);
        $this->subject->buildOptions('c=biws,r=fullnonce,p=proof==', MechanismName::SCRAM_SHA256);
    }

    public function test_it_handles_channel_binding_gs2_header(): void
    {
        $identity = new SaslIdentity('pw', new Dn('cn=user,dc=example,dc=com'));

        $this->mockHandler
            ->method('getSaslIdentity')
            ->willReturn($identity);

        // 'p=tls-unique,,' GS2 header for channel-binding variants
        $this->subject->buildOptions('p=tls-unique,,n=user,r=nonce', MechanismName::SCRAM_SHA256_PLUS);
        $options = $this->subject->buildOptions('c=cD10bHMtdW5pcXVlLCwx,r=fullnonce,p=proof==', MechanismName::SCRAM_SHA256_PLUS);

        self::assertInstanceOf(ScramOptions::class, $options);
    }

    public function test_it_parses_username_from_client_first_without_gs2_header(): void
    {
        $identity = new SaslIdentity('pw', new Dn('cn=user,dc=example,dc=com'));

        $this->mockHandler
            ->expects(self::once())
            ->method('getSaslIdentity')
            ->with('user', MechanismName::SCRAM_SHA256)
            ->willReturn($identity);

        // No ',,' separator — treat the whole string as the bare client-first-message.
        $this->subject->buildOptions('n=user,r=nonce', MechanismName::SCRAM_SHA256);
        $options = $this->subject->buildOptions('c=biws,r=fullnonce,p=proof==', MechanismName::SCRAM_SHA256);

        self::assertInstanceOf(ScramOptions::class, $options);
    }

    public function test_it_throws_protocol_error_when_client_first_has_no_username_field(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::PROTOCOL_ERROR);

        // After stripping the GS2 header the bare message contains no 'n=' field.
        $this->subject->buildOptions('n,,r=nonce-only', MechanismName::SCRAM_SHA256);
    }

    public function test_get_resolved_dn_is_populated_after_successful_client_final(): void
    {
        $identity = new SaslIdentity('pw', new Dn('cn=testuser,dc=example,dc=com'));

        $this->mockHandler
            ->method('getSaslIdentity')
            ->willReturn($identity);

        $this->subject->buildOptions('n,,n=testuser,r=nonce', MechanismName::SCRAM_SHA256);
        $this->subject->buildOptions('c=biws,r=fullnonce,p=proof==', MechanismName::SCRAM_SHA256);

        self::assertSame(
            'cn=testuser,dc=example,dc=com',
            $this->subject->getResolvedDn()?->toString(),
        );
    }
}
