<?php

declare(strict_types=1);

namespace Tests\Unit\FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Control\AssertionControl;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\AssertionEvaluator;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluator;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class AssertionEvaluatorTest extends TestCase
{
    private LdapBackendInterface&MockObject $backend;

    private AssertionEvaluator $subject;

    private Dn $targetDn;

    protected function setUp(): void
    {
        $this->backend = $this->createMock(LdapBackendInterface::class);
        $this->targetDn = new Dn('cn=foo,dc=ex,dc=com');
        $this->subject = new AssertionEvaluator(
            new FilterEvaluator(),
            $this->backend,
        );
    }

    public function test_it_does_nothing_when_no_assertion_control_is_present(): void
    {
        $this->backend
            ->expects(self::never())
            ->method('get');

        $this->subject->assertSatisfied(
            $this->targetDn,
            new ControlBag(),
        );
    }

    public function test_it_passes_when_the_assertion_matches_the_target_entry(): void
    {
        $this->backend
            ->method('get')
            ->with($this->targetDn)
            ->willReturn(Entry::fromArray('cn=foo,dc=ex,dc=com', ['cn' => ['foo']]));

        $this->subject->assertSatisfied(
            $this->targetDn,
            new ControlBag(new AssertionControl(Filters::equal('cn', 'foo'))),
        );
    }

    public function test_it_throws_assertion_failed_when_the_assertion_does_not_match(): void
    {
        $this->backend
            ->method('get')
            ->willReturn(Entry::fromArray('cn=foo,dc=ex,dc=com', ['cn' => ['foo']]));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ASSERTION_FAILED);

        $this->subject->assertSatisfied(
            $this->targetDn,
            new ControlBag(new AssertionControl(Filters::equal('cn', 'bar'))),
        );
    }

    public function test_it_does_not_throw_when_the_target_entry_is_absent(): void
    {
        $this->backend
            ->expects(self::once())
            ->method('get')
            ->with($this->targetDn)
            ->willReturn(null);

        $this->subject->assertSatisfied(
            $this->targetDn,
            new ControlBag(new AssertionControl(Filters::equal('cn', 'bar'))),
        );
    }
}
