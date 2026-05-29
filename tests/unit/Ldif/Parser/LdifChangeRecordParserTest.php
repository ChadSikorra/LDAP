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

namespace Tests\Unit\FreeDSx\Ldap\Ldif\Parser;

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Exception\LdifParseException;
use FreeDSx\Ldap\Ldif\LdifChanges;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use PHPUnit\Framework\TestCase;

final class LdifChangeRecordParserTest extends TestCase
{
    public function test_it_parses_a_changetype_add_record_into_an_add_request(): void
    {
        $result = LdifChanges::fromString(
            "dn: cn=alice,dc=x\nchangetype: add\nobjectClass: top\nobjectClass: person\ncn: alice\nsn: A\n",
        );

        self::assertCount(
            1,
            $result,
        );
        $request = $result->toArray()[0];
        self::assertInstanceOf(
            AddRequest::class,
            $request,
        );
        self::assertSame(
            'cn=alice,dc=x',
            $request->getEntry()->getDn()->toString(),
        );
        self::assertSame(
            ['A'],
            $request->getEntry()->get('sn')?->getValues(),
        );
    }

    public function test_it_parses_a_changetype_delete_record_into_a_delete_request(): void
    {
        $result = LdifChanges::fromString("dn: cn=bob,dc=x\nchangetype: delete\n");

        self::assertCount(
            1,
            $result,
        );
        $request = $result->toArray()[0];
        self::assertInstanceOf(
            DeleteRequest::class,
            $request,
        );
        self::assertSame(
            'cn=bob,dc=x',
            $request->getDn()->toString(),
        );
    }

    public function test_it_rejects_content_after_a_delete_changetype(): void
    {
        $this->expectException(LdifParseException::class);
        $this->expectExceptionMessage('Unexpected directive after "changetype: delete"');

        LdifChanges::fromString("dn: cn=bob,dc=x\nchangetype: delete\ncn: trailing\n");
    }

    public function test_it_parses_a_modify_record_with_a_single_replace_modspec(): void
    {
        $result = LdifChanges::fromString(
            "dn: cn=alice,dc=x\nchangetype: modify\nreplace: sn\nsn: Anderson\n-\n",
        );

        $request = $result->toArray()[0];
        self::assertInstanceOf(
            ModifyRequest::class,
            $request,
        );
        self::assertSame(
            'cn=alice,dc=x',
            $request->getDn()->toString(),
        );
        self::assertCount(
            1,
            $request->getChanges(),
        );
        $change = $request->getChanges()[0];
        self::assertSame(
            Change::TYPE_REPLACE,
            $change->getType(),
        );
        self::assertSame(
            ['Anderson'],
            $change->getAttribute()->getValues(),
        );
    }

    public function test_it_parses_a_modify_record_with_multiple_modspecs_terminated_by_dash(): void
    {
        $result = LdifChanges::fromString(
            "dn: cn=alice,dc=x\nchangetype: modify\n"
            . "add: telephoneNumber\ntelephoneNumber: 555-0100\n-\n"
            . "delete: description\n-\n"
            . "replace: sn\nsn: Anderson\n-\n",
        );

        $request = $result->toArray()[0];
        self::assertInstanceOf(
            ModifyRequest::class,
            $request,
        );
        $changes = $request->getChanges();
        self::assertCount(
            3,
            $changes,
        );
        self::assertSame(
            Change::TYPE_ADD,
            $changes[0]->getType(),
        );
        self::assertSame(
            'telephoneNumber',
            $changes[0]->getAttribute()->getName(),
        );
        self::assertSame(
            Change::TYPE_DELETE,
            $changes[1]->getType(),
        );
        self::assertSame(
            'description',
            $changes[1]->getAttribute()->getName(),
        );
        self::assertSame(
            [],
            $changes[1]->getAttribute()->getValues(),
        );
        self::assertSame(
            Change::TYPE_REPLACE,
            $changes[2]->getType(),
        );
    }

    public function test_it_parses_a_modify_modspec_deleting_a_specific_value(): void
    {
        $result = LdifChanges::fromString(
            "dn: cn=alice,dc=x\nchangetype: modify\ndelete: telephoneNumber\ntelephoneNumber: 555-0100\n-\n",
        );

        $request = $result->toArray()[0];
        self::assertInstanceOf(
            ModifyRequest::class,
            $request,
        );
        $change = $request->getChanges()[0];
        self::assertSame(
            Change::TYPE_DELETE,
            $change->getType(),
        );
        self::assertSame(
            ['555-0100'],
            $change->getAttribute()->getValues(),
        );
    }

    public function test_it_rejects_a_modspec_without_a_dash_terminator(): void
    {
        $this->expectException(LdifParseException::class);
        $this->expectExceptionMessage('missing "-" terminator');

        LdifChanges::fromString("dn: cn=alice,dc=x\nchangetype: modify\nreplace: sn\nsn: Anderson\n");
    }

    public function test_it_rejects_a_modspec_value_with_a_mismatched_attribute(): void
    {
        $this->expectException(LdifParseException::class);
        $this->expectExceptionMessage('does not match values for');

        LdifChanges::fromString(
            "dn: cn=alice,dc=x\nchangetype: modify\nreplace: sn\ncn: not-sn\n-\n",
        );
    }

    public function test_it_rejects_an_unknown_modspec_op(): void
    {
        $this->expectException(LdifParseException::class);
        $this->expectExceptionMessage('Expected an add:, delete:, or replace:');

        LdifChanges::fromString(
            "dn: cn=alice,dc=x\nchangetype: modify\nbogus: sn\nsn: x\n-\n",
        );
    }

    public function test_it_parses_a_modrdn_record_without_newsuperior(): void
    {
        $result = LdifChanges::fromString(
            "dn: cn=alice,dc=x\nchangetype: modrdn\nnewrdn: cn=alicia\ndeleteoldrdn: 1\n",
        );

        $request = $result->toArray()[0];
        self::assertInstanceOf(
            ModifyDnRequest::class,
            $request,
        );
        self::assertSame(
            'cn=alice,dc=x',
            $request->getDn()->toString(),
        );
        self::assertSame(
            'cn=alicia',
            $request->getNewRdn()->toString(),
        );
        self::assertTrue($request->getDeleteOldRdn());
        self::assertNull($request->getNewParentDn());
    }

    public function test_it_parses_a_modrdn_record_with_newsuperior_and_deleteoldrdn_zero(): void
    {
        $result = LdifChanges::fromString(
            "dn: cn=alice,ou=old,dc=x\nchangetype: modrdn\nnewrdn: cn=alicia\ndeleteoldrdn: 0\nnewsuperior: ou=new,dc=x\n",
        );

        $request = $result->toArray()[0];
        self::assertInstanceOf(
            ModifyDnRequest::class,
            $request,
        );
        self::assertFalse($request->getDeleteOldRdn());
        self::assertSame(
            'ou=new,dc=x',
            $request->getNewParentDn()?->toString(),
        );
    }

    public function test_it_decodes_a_base64_newrdn(): void
    {
        $ldif = "dn: cn=foo,dc=x\nchangetype: modrdn\nnewrdn:: " . base64_encode('cn=Bär') . "\ndeleteoldrdn: 1\n";

        $request = LdifChanges::fromString($ldif)->toArray()[0];
        self::assertInstanceOf(
            ModifyDnRequest::class,
            $request,
        );
        self::assertSame(
            'cn=Bär',
            $request->getNewRdn()->toString(),
        );
    }

    public function test_it_rejects_a_modrdn_record_missing_newrdn(): void
    {
        $this->expectException(LdifParseException::class);
        $this->expectExceptionMessage('Missing "newrdn:"');

        LdifChanges::fromString("dn: cn=alice,dc=x\nchangetype: modrdn\ndeleteoldrdn: 1\n");
    }

    public function test_it_rejects_a_modrdn_record_missing_deleteoldrdn(): void
    {
        $this->expectException(LdifParseException::class);
        $this->expectExceptionMessage('Missing "deleteoldrdn:"');

        LdifChanges::fromString("dn: cn=alice,dc=x\nchangetype: modrdn\nnewrdn: cn=alicia\n");
    }

    public function test_it_rejects_deleteoldrdn_that_is_not_zero_or_one(): void
    {
        $this->expectException(LdifParseException::class);
        $this->expectExceptionMessage('must be 0 or 1');

        LdifChanges::fromString(
            "dn: cn=alice,dc=x\nchangetype: modrdn\nnewrdn: cn=alicia\ndeleteoldrdn: 2\n",
        );
    }

    public function test_it_rejects_an_unknown_changetype(): void
    {
        $this->expectException(LdifParseException::class);
        $this->expectExceptionMessage('Unsupported changetype "bogus"');

        LdifChanges::fromString("dn: cn=alice,dc=x\nchangetype: bogus\n");
    }
}
