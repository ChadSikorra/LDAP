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

namespace Tests\Unit\FreeDSx\Ldap\Schema\Validation;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\Schema\StandardSchemaProvider;
use FreeDSx\Ldap\Schema\Validation\SchemaValidator;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use PHPUnit\Framework\TestCase;

final class SchemaValidatorTest extends TestCase
{
    private SchemaValidator $subject;

    protected function setUp(): void
    {
        $this->subject = new SchemaValidator(
            StandardSchemaProvider::buildCore(),
            SchemaValidationMode::Strict,
        );
    }

    private function personEntry(string $dn = 'cn=Alice,dc=example,dc=com'): Entry
    {
        return new Entry(
            new Dn($dn),
            new Attribute('objectClass', 'top', 'person'),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'Smith'),
        );
    }

    public function test_valid_add_passes(): void
    {
        $this->expectNotToPerformAssertions();
        $this->subject->validateAdd($this->personEntry());
    }

    public function test_add_missing_structural_class_throws_object_class_violation(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'top'),
            new Attribute('cn', 'Alice'),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OBJECT_CLASS_VIOLATION);

        $this->subject->validateAdd($entry);
    }

    public function test_add_missing_must_attribute_throws_object_class_violation(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'top', 'person'),
            new Attribute('cn', 'Alice'),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OBJECT_CLASS_VIOLATION);

        $this->subject->validateAdd($entry);
    }

    public function test_add_disallowed_attribute_throws_object_class_violation(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'top', 'person'),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'Smith'),
            new Attribute('employeeNumber', '42'),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OBJECT_CLASS_VIOLATION);

        $this->subject->validateAdd($entry);
    }

    public function test_add_undefined_attribute_type_throws(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'top', 'person'),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'Smith'),
            new Attribute('unknownAttr99', 'value'),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::UNDEFINED_ATTRIBUTE_TYPE);

        $this->subject->validateAdd($entry);
    }

    public function test_add_single_valued_violation_throws_constraint_violation(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'top', 'person', 'organizationalPerson', 'inetOrgPerson'),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'Smith'),
            new Attribute('employeeNumber', '001', '002'),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        $this->subject->validateAdd($entry);
    }

    public function test_add_no_user_modification_attribute_throws_constraint_violation(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'top', 'person'),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'Smith'),
            new Attribute('createTimestamp', '20240101000000Z'),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        $this->subject->validateAdd($entry);
    }

    public function test_add_extensible_object_bypasses_attribute_checks(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'extensibleObject'),
            new Attribute('anyAttr', 'value'),
        );

        $this->expectNotToPerformAssertions();
        $this->subject->validateAdd($entry);
    }

    public function test_valid_modify_passes(): void
    {
        $this->expectNotToPerformAssertions();

        $command = new UpdateCommand(
            new Dn('cn=Alice,dc=example,dc=com'),
            [Change::replace(new Attribute('sn', 'Jones'))],
        );
        $result = $this->personEntry();

        $this->subject->validateModify($command, $result);
    }

    public function test_modify_no_user_modification_attribute_throws_constraint_violation(): void
    {
        $command = new UpdateCommand(
            new Dn('cn=Alice,dc=example,dc=com'),
            [Change::replace(new Attribute('createTimestamp', '20240101000000Z'))],
        );
        $result = $this->personEntry();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        $this->subject->validateModify($command, $result);
    }

    public function test_off_mode_does_not_throw_on_violations(): void
    {
        $subject = new SchemaValidator(
            StandardSchemaProvider::buildCore(),
            SchemaValidationMode::Off,
        );

        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'top'),
        );

        $this->expectNotToPerformAssertions();
        $subject->validateAdd($entry);
    }

    public function test_system_add_skips_no_user_modification_but_keeps_structure_checks(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'top', 'person'),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'Smith'),
            new Attribute('createTimestamp', '20240101000000Z'),
        );

        $this->expectNotToPerformAssertions();

        $this->subject->validateAdd(
            $entry,
            isSystem: true,
        );
    }

    public function test_system_add_still_enforces_structural_class(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'top'),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OBJECT_CLASS_VIOLATION);

        $this->subject->validateAdd(
            $entry,
            isSystem: true,
        );
    }

    public function test_system_modify_skips_no_user_modification_check(): void
    {
        $command = new UpdateCommand(
            new Dn('cn=Alice,dc=example,dc=com'),
            [Change::replace(new Attribute('createTimestamp', '20240101000000Z'))],
        );
        $result = $this->personEntry();

        $this->expectNotToPerformAssertions();

        $this->subject->validateModify(
            $command,
            $result,
            isSystem: true,
        );
    }

    public function test_system_modify_still_enforces_single_valued_attribute(): void
    {
        $command = new UpdateCommand(
            new Dn('cn=Alice,dc=example,dc=com'),
            [Change::replace(new Attribute('createTimestamp', '20240101000000Z', '20240202000000Z'))],
        );
        $result = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'top', 'person'),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'Smith'),
            new Attribute('createTimestamp', '20240101000000Z', '20240202000000Z'),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        $this->subject->validateModify(
            $command,
            $result,
            isSystem: true,
        );
    }
}
