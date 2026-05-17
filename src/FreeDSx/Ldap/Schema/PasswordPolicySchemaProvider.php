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

namespace FreeDSx\Ldap\Schema;

use FreeDSx\Ldap\Schema\Definition\AttributeType;
use FreeDSx\Ldap\Schema\Definition\AttributeUsage;
use FreeDSx\Ldap\Schema\Definition\MatchingRuleOid;
use FreeDSx\Ldap\Schema\Definition\ObjectClass;
use FreeDSx\Ldap\Schema\Definition\ObjectClassType;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Schema\Definition\SyntaxOid;

/**
 * Builds the draft-behera-ldap-password-policy-10 attribute types and the pwdPolicy auxiliary class.
 */
final class PasswordPolicySchemaProvider
{
    public static function build(): Schema
    {
        $schema = new Schema();

        foreach (self::attributeTypes() as $type) {
            $schema->addAttributeType($type);
        }
        foreach (self::objectClasses() as $class) {
            $schema->addObjectClass($class);
        }

        return $schema;
    }

    /**
     * @return list<AttributeType>
     */
    private static function attributeTypes(): array
    {
        return [
            ...self::policyConfigAttributes(),
            ...self::userStateAttributes(),
        ];
    }

    /**
     * @return list<AttributeType>
     */
    private static function policyConfigAttributes(): array
    {
        return [
            new AttributeType(
                PasswordPolicyOid::OID_PWD_ATTRIBUTE,
                [PasswordPolicyOid::NAME_PWD_ATTRIBUTE],
                equalityOid: MatchingRuleOid::OID_OBJECT_IDENTIFIER_MATCH,
                syntaxOid: SyntaxOid::OID_OID,
                singleValue: true,
                desc: PasswordPolicyOid::DESC_PWD_ATTRIBUTE,
            ),
            self::integer(
                PasswordPolicyOid::OID_PWD_MIN_AGE,
                PasswordPolicyOid::NAME_PWD_MIN_AGE,
                PasswordPolicyOid::DESC_PWD_MIN_AGE,
            ),
            self::integer(
                PasswordPolicyOid::OID_PWD_MAX_AGE,
                PasswordPolicyOid::NAME_PWD_MAX_AGE,
                PasswordPolicyOid::DESC_PWD_MAX_AGE,
            ),
            self::integer(
                PasswordPolicyOid::OID_PWD_IN_HISTORY,
                PasswordPolicyOid::NAME_PWD_IN_HISTORY,
                PasswordPolicyOid::DESC_PWD_IN_HISTORY,
            ),
            self::integer(
                PasswordPolicyOid::OID_PWD_CHECK_QUALITY,
                PasswordPolicyOid::NAME_PWD_CHECK_QUALITY,
                PasswordPolicyOid::DESC_PWD_CHECK_QUALITY,
            ),
            self::integer(
                PasswordPolicyOid::OID_PWD_MIN_LENGTH,
                PasswordPolicyOid::NAME_PWD_MIN_LENGTH,
                PasswordPolicyOid::DESC_PWD_MIN_LENGTH,
            ),
            self::integer(
                PasswordPolicyOid::OID_PWD_EXPIRE_WARNING,
                PasswordPolicyOid::NAME_PWD_EXPIRE_WARNING,
                PasswordPolicyOid::DESC_PWD_EXPIRE_WARNING,
            ),
            self::integer(
                PasswordPolicyOid::OID_PWD_GRACE_AUTHN_LIMIT,
                PasswordPolicyOid::NAME_PWD_GRACE_AUTHN_LIMIT,
                PasswordPolicyOid::DESC_PWD_GRACE_AUTHN_LIMIT,
            ),
            self::boolean(
                PasswordPolicyOid::OID_PWD_LOCKOUT,
                PasswordPolicyOid::NAME_PWD_LOCKOUT,
                PasswordPolicyOid::DESC_PWD_LOCKOUT,
            ),
            self::integer(
                PasswordPolicyOid::OID_PWD_LOCKOUT_DURATION,
                PasswordPolicyOid::NAME_PWD_LOCKOUT_DURATION,
                PasswordPolicyOid::DESC_PWD_LOCKOUT_DURATION,
            ),
            self::integer(
                PasswordPolicyOid::OID_PWD_MAX_FAILURE,
                PasswordPolicyOid::NAME_PWD_MAX_FAILURE,
                PasswordPolicyOid::DESC_PWD_MAX_FAILURE,
            ),
            self::integer(
                PasswordPolicyOid::OID_PWD_FAILURE_COUNT_INTERVAL,
                PasswordPolicyOid::NAME_PWD_FAILURE_COUNT_INTERVAL,
                PasswordPolicyOid::DESC_PWD_FAILURE_COUNT_INTERVAL,
            ),
            self::boolean(
                PasswordPolicyOid::OID_PWD_MUST_CHANGE,
                PasswordPolicyOid::NAME_PWD_MUST_CHANGE,
                PasswordPolicyOid::DESC_PWD_MUST_CHANGE,
            ),
            self::boolean(
                PasswordPolicyOid::OID_PWD_ALLOW_USER_CHANGE,
                PasswordPolicyOid::NAME_PWD_ALLOW_USER_CHANGE,
                PasswordPolicyOid::DESC_PWD_ALLOW_USER_CHANGE,
            ),
            self::boolean(
                PasswordPolicyOid::OID_PWD_SAFE_MODIFY,
                PasswordPolicyOid::NAME_PWD_SAFE_MODIFY,
                PasswordPolicyOid::DESC_PWD_SAFE_MODIFY,
            ),
            self::integer(
                PasswordPolicyOid::OID_PWD_MIN_DELAY,
                PasswordPolicyOid::NAME_PWD_MIN_DELAY,
                PasswordPolicyOid::DESC_PWD_MIN_DELAY,
            ),
            self::integer(
                PasswordPolicyOid::OID_PWD_MAX_DELAY,
                PasswordPolicyOid::NAME_PWD_MAX_DELAY,
                PasswordPolicyOid::DESC_PWD_MAX_DELAY,
            ),
            self::integer(
                PasswordPolicyOid::OID_PWD_MAX_IDLE,
                PasswordPolicyOid::NAME_PWD_MAX_IDLE,
                PasswordPolicyOid::DESC_PWD_MAX_IDLE,
            ),
            self::integer(
                PasswordPolicyOid::OID_PWD_GRACE_EXPIRY,
                PasswordPolicyOid::NAME_PWD_GRACE_EXPIRY,
                PasswordPolicyOid::DESC_PWD_GRACE_EXPIRY,
            ),
            self::integer(
                PasswordPolicyOid::OID_PWD_MAX_LENGTH,
                PasswordPolicyOid::NAME_PWD_MAX_LENGTH,
                PasswordPolicyOid::DESC_PWD_MAX_LENGTH,
            ),
        ];
    }

    /**
     * @return list<AttributeType>
     */
    private static function userStateAttributes(): array
    {
        return [
            self::operationalGeneralizedTime(
                PasswordPolicyOid::OID_PWD_CHANGED_TIME,
                PasswordPolicyOid::NAME_PWD_CHANGED_TIME,
                PasswordPolicyOid::DESC_PWD_CHANGED_TIME,
                singleValue: true,
            ),
            self::operationalGeneralizedTime(
                PasswordPolicyOid::OID_PWD_ACCOUNT_LOCKED_TIME,
                PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME,
                PasswordPolicyOid::DESC_PWD_ACCOUNT_LOCKED_TIME,
                singleValue: true,
            ),
            self::operationalGeneralizedTime(
                PasswordPolicyOid::OID_PWD_FAILURE_TIME,
                PasswordPolicyOid::NAME_PWD_FAILURE_TIME,
                PasswordPolicyOid::DESC_PWD_FAILURE_TIME,
                singleValue: false,
            ),
            new AttributeType(
                PasswordPolicyOid::OID_PWD_HISTORY,
                [PasswordPolicyOid::NAME_PWD_HISTORY],
                equalityOid: MatchingRuleOid::OID_OCTET_STRING_MATCH,
                syntaxOid: SyntaxOid::OID_OCTET_STRING,
                noUserModification: true,
                usage: AttributeUsage::DirectoryOperation,
                desc: PasswordPolicyOid::DESC_PWD_HISTORY,
            ),
            new AttributeType(
                PasswordPolicyOid::OID_PWD_GRACE_USE_TIME,
                [PasswordPolicyOid::NAME_PWD_GRACE_USE_TIME],
                equalityOid: MatchingRuleOid::OID_GENERALIZED_TIME_MATCH,
                syntaxOid: SyntaxOid::OID_GENERALIZED_TIME,
                noUserModification: true,
                usage: AttributeUsage::DirectoryOperation,
                desc: PasswordPolicyOid::DESC_PWD_GRACE_USE_TIME,
            ),
            self::operationalGeneralizedTime(
                PasswordPolicyOid::OID_PWD_START_TIME,
                PasswordPolicyOid::NAME_PWD_START_TIME,
                PasswordPolicyOid::DESC_PWD_START_TIME,
                singleValue: true,
            ),
            self::operationalGeneralizedTime(
                PasswordPolicyOid::OID_PWD_END_TIME,
                PasswordPolicyOid::NAME_PWD_END_TIME,
                PasswordPolicyOid::DESC_PWD_END_TIME,
                singleValue: true,
            ),
            self::operationalGeneralizedTime(
                PasswordPolicyOid::OID_PWD_LAST_SUCCESS,
                PasswordPolicyOid::NAME_PWD_LAST_SUCCESS,
                PasswordPolicyOid::DESC_PWD_LAST_SUCCESS,
                singleValue: true,
            ),
            new AttributeType(
                PasswordPolicyOid::OID_PWD_RESET,
                [PasswordPolicyOid::NAME_PWD_RESET],
                equalityOid: MatchingRuleOid::OID_BOOLEAN_MATCH,
                syntaxOid: SyntaxOid::OID_BOOLEAN,
                singleValue: true,
                noUserModification: true,
                usage: AttributeUsage::DirectoryOperation,
                desc: PasswordPolicyOid::DESC_PWD_RESET,
            ),
            new AttributeType(
                PasswordPolicyOid::OID_PWD_POLICY_SUBENTRY,
                [PasswordPolicyOid::NAME_PWD_POLICY_SUBENTRY],
                equalityOid: MatchingRuleOid::OID_DISTINGUISHED_NAME_MATCH,
                syntaxOid: SyntaxOid::OID_DISTINGUISHED_NAME,
                singleValue: true,
                noUserModification: true,
                usage: AttributeUsage::DirectoryOperation,
                desc: PasswordPolicyOid::DESC_PWD_POLICY_SUBENTRY,
            ),
        ];
    }

    /**
     * @return list<ObjectClass>
     */
    private static function objectClasses(): array
    {
        return [
            new ObjectClass(
                PasswordPolicyOid::OID_PWD_POLICY,
                [PasswordPolicyOid::NAME_PWD_POLICY],
                type: ObjectClassType::AuxiliaryClass,
                must: [PasswordPolicyOid::NAME_PWD_ATTRIBUTE],
                may: [
                    PasswordPolicyOid::NAME_PWD_MIN_AGE,
                    PasswordPolicyOid::NAME_PWD_MAX_AGE,
                    PasswordPolicyOid::NAME_PWD_IN_HISTORY,
                    PasswordPolicyOid::NAME_PWD_CHECK_QUALITY,
                    PasswordPolicyOid::NAME_PWD_MIN_LENGTH,
                    PasswordPolicyOid::NAME_PWD_MAX_LENGTH,
                    PasswordPolicyOid::NAME_PWD_EXPIRE_WARNING,
                    PasswordPolicyOid::NAME_PWD_GRACE_AUTHN_LIMIT,
                    PasswordPolicyOid::NAME_PWD_GRACE_EXPIRY,
                    PasswordPolicyOid::NAME_PWD_LOCKOUT,
                    PasswordPolicyOid::NAME_PWD_LOCKOUT_DURATION,
                    PasswordPolicyOid::NAME_PWD_MAX_FAILURE,
                    PasswordPolicyOid::NAME_PWD_FAILURE_COUNT_INTERVAL,
                    PasswordPolicyOid::NAME_PWD_MUST_CHANGE,
                    PasswordPolicyOid::NAME_PWD_ALLOW_USER_CHANGE,
                    PasswordPolicyOid::NAME_PWD_SAFE_MODIFY,
                    PasswordPolicyOid::NAME_PWD_MIN_DELAY,
                    PasswordPolicyOid::NAME_PWD_MAX_DELAY,
                    PasswordPolicyOid::NAME_PWD_MAX_IDLE,
                ],
                desc: PasswordPolicyOid::DESC_PWD_POLICY,
            ),
        ];
    }

    private static function integer(
        string $oid,
        string $name,
        string $desc,
    ): AttributeType {
        return new AttributeType(
            $oid,
            [$name],
            equalityOid: MatchingRuleOid::OID_INTEGER_MATCH,
            orderingOid: MatchingRuleOid::OID_INTEGER_ORDERING_MATCH,
            syntaxOid: SyntaxOid::OID_INTEGER,
            singleValue: true,
            desc: $desc,
        );
    }

    private static function boolean(
        string $oid,
        string $name,
        string $desc,
    ): AttributeType {
        return new AttributeType(
            $oid,
            [$name],
            equalityOid: MatchingRuleOid::OID_BOOLEAN_MATCH,
            syntaxOid: SyntaxOid::OID_BOOLEAN,
            singleValue: true,
            desc: $desc,
        );
    }

    private static function operationalGeneralizedTime(
        string $oid,
        string $name,
        string $desc,
        bool $singleValue,
    ): AttributeType {
        return new AttributeType(
            $oid,
            [$name],
            equalityOid: MatchingRuleOid::OID_GENERALIZED_TIME_MATCH,
            orderingOid: MatchingRuleOid::OID_GENERALIZED_TIME_ORDERING_MATCH,
            syntaxOid: SyntaxOid::OID_GENERALIZED_TIME,
            singleValue: $singleValue,
            noUserModification: true,
            usage: AttributeUsage::DirectoryOperation,
            desc: $desc,
        );
    }
}
