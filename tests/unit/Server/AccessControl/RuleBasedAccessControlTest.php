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

namespace Tests\Unit\FreeDSx\Ldap\Server\AccessControl;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\AccessControl\AclRules;
use FreeDSx\Ldap\Server\AccessControl\OperationType;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\ControlRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\Effect;
use FreeDSx\Ldap\Server\AccessControl\Rule\OperationRule;
use FreeDSx\Ldap\Server\AccessControl\RuleBasedAccessControl;
use FreeDSx\Ldap\Server\AccessControl\BackendAwareInterface;
use FreeDSx\Ldap\Server\AccessControl\Subject\AnySubjectMatcher;
use FreeDSx\Ldap\Server\AccessControl\Subject\SubjectMatcherInterface;
use FreeDSx\Ldap\Server\AccessControl\Target\AnyTargetMatcher;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class RuleBasedAccessControlTest extends TestCase
{
    private Dn $dn;

    private TokenInterface $bindToken;

    protected function setUp(): void
    {
        $this->dn = new Dn('dc=foo,dc=bar');
        $this->bindToken = BindToken::fromDn(
            'cn=admin,dc=foo,dc=bar',
            'secret',
        );
    }

    public function test_it_should_allow_when_first_matching_rule_is_allow(): void
    {
        $this->expectNotToPerformAssertions();

        $subject = new RuleBasedAccessControl(new AclRules(
            operations: [
                OperationRule::allow(new AnySubjectMatcher()),
            ],
        ));

        $subject->authorizeOperation(
            OperationType::Search,
            $this->bindToken,
            $this->dn,
        );
    }

    public function test_it_should_deny_when_first_matching_rule_is_deny(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $subject = new RuleBasedAccessControl(new AclRules(
            operations: [
                OperationRule::deny(new AnySubjectMatcher()),
            ],
        ));

        $subject->authorizeOperation(
            OperationType::Search,
            $this->bindToken,
            $this->dn,
        );
    }

    public function test_it_should_deny_when_no_rules_match_and_default_effect_is_deny(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $subject = new RuleBasedAccessControl(new AclRules(defaultOperationEffect: Effect::Deny));

        $subject->authorizeOperation(
            OperationType::Search,
            $this->bindToken,
            $this->dn,
        );
    }

    public function test_it_should_allow_when_no_rules_match_and_default_effect_is_allow(): void
    {
        $this->expectNotToPerformAssertions();

        $subject = new RuleBasedAccessControl(new AclRules(defaultOperationEffect: Effect::Allow));

        $subject->authorizeOperation(
            OperationType::Search,
            $this->bindToken,
            $this->dn,
        );
    }

    public function test_it_should_skip_rule_when_operation_type_does_not_match(): void
    {
        $this->expectException(OperationException::class);

        $subject = new RuleBasedAccessControl(new AclRules(
            operations: [
                OperationRule::allow(
                    new AnySubjectMatcher(),
                    new AnyTargetMatcher(),
                    OperationType::Add,
                ),
            ],
            defaultOperationEffect: Effect::Deny,
        ));

        $subject->authorizeOperation(
            OperationType::Search,
            $this->bindToken,
            $this->dn,
        );
    }

    public function test_it_should_apply_rule_when_operation_type_matches(): void
    {
        $this->expectNotToPerformAssertions();

        $subject = new RuleBasedAccessControl(new AclRules(
            operations: [
                OperationRule::allow(
                    new AnySubjectMatcher(),
                    new AnyTargetMatcher(),
                    OperationType::Search,
                ),
            ],
        ));

        $subject->authorizeOperation(
            OperationType::Search,
            $this->bindToken,
            $this->dn,
        );
    }

    public function test_it_should_apply_rule_with_empty_operations_list_to_all_operation_types(): void
    {
        $this->expectNotToPerformAssertions();

        $subject = new RuleBasedAccessControl(new AclRules(
            operations: [
                OperationRule::allow(new AnySubjectMatcher()),
            ],
        ));

        foreach (OperationType::cases() as $type) {
            $subject->authorizeOperation(
                $type,
                $this->bindToken,
                $this->dn,
            );
        }
    }

    public function test_it_should_use_first_match_when_deny_rule_precedes_allow_rule(): void
    {
        $this->expectException(OperationException::class);

        $subject = new RuleBasedAccessControl(new AclRules(
            operations: [
                OperationRule::deny(new AnySubjectMatcher()),
                OperationRule::allow(new AnySubjectMatcher()),
            ],
        ));

        $subject->authorizeOperation(
            OperationType::Search,
            $this->bindToken,
            $this->dn,
        );
    }

    public function test_may_use_control_is_true_when_an_allow_rule_matches_the_subject(): void
    {
        $subject = new RuleBasedAccessControl(new AclRules(
            controls: [
                ControlRule::allow(
                    new AnySubjectMatcher(),
                    new AnyTargetMatcher(),
                    Control::OID_PROXY_AUTHORIZATION,
                ),
            ],
        ));

        self::assertTrue($subject->mayUseControl(
            $this->bindToken,
            Control::OID_PROXY_AUTHORIZATION,
        ));
    }

    public function test_may_use_control_is_false_when_no_rule_grants_the_control(): void
    {
        $subject = new RuleBasedAccessControl(new AclRules(
            controls: [
                ControlRule::allow(
                    new AnySubjectMatcher(),
                    new AnyTargetMatcher(),
                    Control::OID_RELAX_RULES,
                ),
            ],
        ));

        self::assertFalse($subject->mayUseControl(
            $this->bindToken,
            Control::OID_PROXY_AUTHORIZATION,
        ));
    }

    public function test_may_use_control_is_false_for_an_unauthenticated_token(): void
    {
        $subject = new RuleBasedAccessControl(new AclRules(
            controls: [
                ControlRule::allow(
                    new AnySubjectMatcher(),
                    new AnyTargetMatcher(),
                    Control::OID_PROXY_AUTHORIZATION,
                ),
            ],
        ));

        self::assertFalse($subject->mayUseControl(
            new AnonToken(),
            Control::OID_PROXY_AUTHORIZATION,
        ));
    }

    public function test_filter_entry_returns_same_instance_when_no_attribute_rules(): void
    {
        $entry = Entry::create('dc=foo,dc=bar', ['cn' => 'foo']);

        $subject = new RuleBasedAccessControl(new AclRules(
            operations: [OperationRule::allow(new AnySubjectMatcher())],
        ));

        $result = $subject->filterEntry(
            $this->bindToken,
            $entry,
        );

        self::assertSame($entry, $result);
    }

    public function test_filter_entry_removes_attribute_when_deny_rule_matches(): void
    {
        $entry = Entry::create(
            'dc=foo,dc=bar',
            ['cn' => 'foo', 'userpassword' => 'secret'],
        );

        $subject = new RuleBasedAccessControl(new AclRules(
            operations: [OperationRule::allow(new AnySubjectMatcher())],
            attributes: [
                AttributeRule::deny(
                    new AnySubjectMatcher(),
                    new AnyTargetMatcher(),
                    'userPassword',
                ),
            ],
        ));

        $result = $subject->filterEntry(
            $this->bindToken,
            $entry,
        );

        self::assertNotNull($result);
        self::assertNull($result->get('userPassword'));
        self::assertNotNull($result->get('cn'));
    }

    public function test_filter_entry_keeps_attribute_when_allow_rule_precedes_deny_rule(): void
    {
        $matchingSubject = $this->createMock(SubjectMatcherInterface::class);
        $matchingSubject->method('matches')->willReturn(true);

        $entry = Entry::create(
            'dc=foo,dc=bar',
            ['userpassword' => 'secret'],
        );

        $subject = new RuleBasedAccessControl(new AclRules(
            operations: [OperationRule::allow(new AnySubjectMatcher())],
            attributes: [
                AttributeRule::allow(
                    $matchingSubject,
                    new AnyTargetMatcher(),
                    'userPassword',
                ),
                AttributeRule::deny(
                    new AnySubjectMatcher(),
                    new AnyTargetMatcher(),
                    'userPassword',
                ),
            ],
        ));

        $result = $subject->filterEntry(
            $this->bindToken,
            $entry,
        );

        self::assertNotNull($result);
        self::assertNotNull($result->get('userPassword'));
    }

    public function test_filter_entry_keeps_attribute_when_no_rule_matches(): void
    {
        $nonMatchingSubject = $this->createMock(SubjectMatcherInterface::class);
        $nonMatchingSubject->method('matches')->willReturn(false);

        $entry = Entry::create(
            'dc=foo,dc=bar',
            ['cn' => 'foo'],
        );

        $subject = new RuleBasedAccessControl(new AclRules(
            operations: [OperationRule::allow(new AnySubjectMatcher())],
            attributes: [
                AttributeRule::deny(
                    $nonMatchingSubject,
                    new AnyTargetMatcher(),
                    'cn',
                ),
            ],
        ));

        $result = $subject->filterEntry(
            $this->bindToken,
            $entry,
        );

        self::assertNotNull($result);
        self::assertNotNull($result->get('cn'));
    }

    public function test_filter_entry_returns_same_instance_when_all_attributes_kept(): void
    {
        $entry = Entry::create(
            'dc=foo,dc=bar',
            ['cn' => 'foo'],
        );

        $subject = new RuleBasedAccessControl(new AclRules(
            operations: [OperationRule::allow(new AnySubjectMatcher())],
            attributes: [
                AttributeRule::allow(
                    new AnySubjectMatcher(),
                    new AnyTargetMatcher(),
                    'cn',
                ),
            ],
        ));

        $result = $subject->filterEntry(
            $this->bindToken,
            $entry,
        );

        self::assertSame($entry, $result);
    }

    public function test_filter_entry_empty_attributes_list_on_deny_rule_matches_all_attributes(): void
    {
        $entry = Entry::create(
            'dc=foo,dc=bar',
            ['cn' => 'foo', 'sn' => 'bar'],
        );

        $subject = new RuleBasedAccessControl(new AclRules(
            operations: [OperationRule::allow(new AnySubjectMatcher())],
            attributes: [
                AttributeRule::deny(new AnySubjectMatcher()),
            ],
        ));

        $result = $subject->filterEntry(
            $this->bindToken,
            $entry,
        );

        self::assertNotNull($result);
        self::assertEmpty($result->getAttributes());
    }

    public function test_filter_entry_returns_null_when_search_operation_is_denied_on_entry_dn(): void
    {
        $entry = Entry::create(
            'dc=foo,dc=bar',
            ['cn' => 'foo'],
        );

        $subject = new RuleBasedAccessControl(new AclRules(
            operations: [
                OperationRule::deny(
                    new AnySubjectMatcher(),
                    new AnyTargetMatcher(),
                    OperationType::Search,
                ),
            ],
        ));

        $result = $subject->filterEntry(
            $this->bindToken,
            $entry,
        );

        self::assertNull($result);
    }

    public function test_authorize_attribute_access_does_not_throw_when_no_deny_rule_matches(): void
    {
        $this->expectNotToPerformAssertions();

        $subject = new RuleBasedAccessControl();

        $subject->authorizeAttribute(
            $this->bindToken,
            $this->dn,
            'userPassword',
        );
    }

    public function test_authorize_attribute_access_throws_when_deny_rule_matches(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $subject = new RuleBasedAccessControl(new AclRules(
            attributes: [
                AttributeRule::deny(
                    new AnySubjectMatcher(),
                    new AnyTargetMatcher(),
                    'userPassword',
                ),
            ],
        ));

        $subject->authorizeAttribute(
            $this->bindToken,
            $this->dn,
            'userPassword',
        );
    }

    public function test_authorize_control_denies_by_default(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $subject = new RuleBasedAccessControl();

        $subject->authorizeControl(
            $this->bindToken,
            $this->dn,
            Control::OID_RELAX_RULES,
        );
    }

    public function test_authorize_control_allows_when_control_rule_grants_the_oid(): void
    {
        $this->expectNotToPerformAssertions();

        $subject = new RuleBasedAccessControl(new AclRules(
            controls: [
                ControlRule::allow(
                    new AnySubjectMatcher(),
                    new AnyTargetMatcher(),
                    Control::OID_RELAX_RULES,
                ),
            ],
        ));

        $subject->authorizeControl(
            $this->bindToken,
            $this->dn,
            Control::OID_RELAX_RULES,
        );
    }

    public function test_authorize_control_denies_when_rule_grants_a_different_oid(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $subject = new RuleBasedAccessControl(new AclRules(
            controls: [
                ControlRule::allow(
                    new AnySubjectMatcher(),
                    new AnyTargetMatcher(),
                    Control::OID_SUBTREE_DELETE,
                ),
            ],
        ));

        $subject->authorizeControl(
            $this->bindToken,
            $this->dn,
            Control::OID_RELAX_RULES,
        );
    }

    public function test_authorize_control_denies_when_deny_rule_matches(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $subject = new RuleBasedAccessControl(new AclRules(
            controls: [
                ControlRule::deny(new AnySubjectMatcher()),
            ],
        ));

        $subject->authorizeControl(
            $this->bindToken,
            $this->dn,
            Control::OID_RELAX_RULES,
        );
    }

    public function test_set_backend_propagates_to_backend_aware_subjects(): void
    {
        $mockBackend = $this->createMock(LdapBackendInterface::class);

        /** @var SubjectMatcherInterface&BackendAwareInterface&MockObject $mockBackendAwareSubject */
        $mockBackendAwareSubject = $this->createMockForIntersectionOfInterfaces([
            SubjectMatcherInterface::class,
            BackendAwareInterface::class,
        ]);

        $mockBackendAwareSubject
            ->expects(self::once())
            ->method('setBackend')
            ->with($mockBackend);

        $subject = new RuleBasedAccessControl(new AclRules(
            operations: [OperationRule::allow($mockBackendAwareSubject)],
        ));

        $subject->setBackend($mockBackend);
    }
}
