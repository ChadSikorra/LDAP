<?php

declare(strict_types=1);

namespace Tests\Unit\FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\ReadEntry\PostReadControl;
use FreeDSx\Ldap\Control\ReadEntry\PostReadResponseControl;
use FreeDSx\Ldap\Control\ReadEntry\PreReadControl;
use FreeDSx\Ldap\Control\ReadEntry\PreReadResponseControl;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ReadEntryControlHandler;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ReadEntryControlHandlerTest extends TestCase
{
    private LdapBackendInterface&MockObject $backend;

    private ReadEntryControlHandler $subject;

    private Dn $dn;

    protected function setUp(): void
    {
        $this->backend = $this->createMock(LdapBackendInterface::class);
        $this->dn = new Dn('cn=foo,dc=ex,dc=com');
        $this->subject = new ReadEntryControlHandler(
            $this->backend,
            new Schema(),
        );
    }

    public function test_pre_read_returns_null_without_the_control(): void
    {
        $this->backend
            ->expects(self::never())
            ->method('get');

        self::assertNull(
            $this->subject->preRead($this->dn, new ControlBag()),
        );
    }

    public function test_post_read_returns_null_without_the_control(): void
    {
        self::assertNull(
            $this->subject->postRead($this->dn, new ControlBag()),
        );
    }

    public function test_pre_read_returns_null_when_the_entry_is_absent(): void
    {
        $this->backend
            ->method('get')
            ->willReturn(null);

        self::assertNull(
            $this->subject->preRead($this->dn, new ControlBag(new PreReadControl())),
        );
    }

    public function test_pre_read_returns_a_response_control_with_the_entry(): void
    {
        $this->backend
            ->method('get')
            ->willReturn(Entry::fromArray('cn=foo,dc=ex,dc=com', ['cn' => ['foo']]));

        $control = $this->subject->preRead(
            $this->dn,
            new ControlBag(new PreReadControl()),
        );

        self::assertInstanceOf(PreReadResponseControl::class, $control);
        self::assertSame(
            'cn=foo,dc=ex,dc=com',
            $control->getEntry()->getDn()->toString(),
        );
    }

    public function test_post_read_projects_only_the_requested_attributes(): void
    {
        $this->backend
            ->method('get')
            ->willReturn(Entry::fromArray('cn=foo,dc=ex,dc=com', [
                'cn' => ['foo'],
                'sn' => ['bar'],
            ]));

        $control = $this->subject->postRead(
            $this->dn,
            new ControlBag(new PostReadControl('cn')),
        );

        self::assertInstanceOf(PostReadResponseControl::class, $control);
        self::assertSame(
            ['cn'],
            array_map(
                static fn($attr): string => $attr->getName(),
                $control->getEntry()->getAttributes(),
            ),
        );
    }

    public function test_the_snapshot_is_isolated_from_later_mutation_of_the_stored_entry(): void
    {
        $stored = Entry::fromArray('cn=foo,dc=ex,dc=com', ['cn' => ['foo']]);
        $this->backend
            ->method('get')
            ->willReturn($stored);

        $control = $this->subject->preRead(
            $this->dn,
            new ControlBag(new PreReadControl()),
        );

        // Mutate the stored entry in place after the snapshot was taken.
        $stored->get('cn')?->add('changed');

        self::assertInstanceOf(PreReadResponseControl::class, $control);
        self::assertSame(
            ['foo'],
            $control->getEntry()->get('cn')?->getValues(),
        );
    }
}
