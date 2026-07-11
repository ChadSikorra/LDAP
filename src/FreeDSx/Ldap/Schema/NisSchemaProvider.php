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
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Schema\Definition\MatchingRuleOid;
use FreeDSx\Ldap\Schema\Definition\Nis\AttributeTypeOid as NisAttributeTypeOid;
use FreeDSx\Ldap\Schema\Definition\Nis\ObjectClassOid as NisObjectClassOid;
use FreeDSx\Ldap\Schema\Definition\ObjectClass;
use FreeDSx\Ldap\Schema\Definition\ObjectClassOid;
use FreeDSx\Ldap\Schema\Definition\ObjectClassType;
use FreeDSx\Ldap\Schema\Definition\SyntaxOid;

/**
 * Builds the RFC 2307 POSIX account/group/shadow schema.
 *
 * @api
 */
final class NisSchemaProvider
{
    private function __construct() {}

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
            self::integer(
                NisAttributeTypeOid::OID_UID_NUMBER,
                NisAttributeTypeOid::NAME_UID_NUMBER,
                NisAttributeTypeOid::DESC_UID_NUMBER,
            ),
            self::integer(
                NisAttributeTypeOid::OID_GID_NUMBER,
                NisAttributeTypeOid::NAME_GID_NUMBER,
                NisAttributeTypeOid::DESC_GID_NUMBER,
            ),
            self::integer(
                NisAttributeTypeOid::OID_SHADOW_LAST_CHANGE,
                NisAttributeTypeOid::NAME_SHADOW_LAST_CHANGE,
                NisAttributeTypeOid::DESC_SHADOW_LAST_CHANGE,
            ),
            self::integer(
                NisAttributeTypeOid::OID_SHADOW_MIN,
                NisAttributeTypeOid::NAME_SHADOW_MIN,
                NisAttributeTypeOid::DESC_SHADOW_MIN,
            ),
            self::integer(
                NisAttributeTypeOid::OID_SHADOW_MAX,
                NisAttributeTypeOid::NAME_SHADOW_MAX,
                NisAttributeTypeOid::DESC_SHADOW_MAX,
            ),
            self::integer(
                NisAttributeTypeOid::OID_SHADOW_WARNING,
                NisAttributeTypeOid::NAME_SHADOW_WARNING,
                NisAttributeTypeOid::DESC_SHADOW_WARNING,
            ),
            self::integer(
                NisAttributeTypeOid::OID_SHADOW_INACTIVE,
                NisAttributeTypeOid::NAME_SHADOW_INACTIVE,
                NisAttributeTypeOid::DESC_SHADOW_INACTIVE,
            ),
            self::integer(
                NisAttributeTypeOid::OID_SHADOW_EXPIRE,
                NisAttributeTypeOid::NAME_SHADOW_EXPIRE,
                NisAttributeTypeOid::DESC_SHADOW_EXPIRE,
            ),
            self::integer(
                NisAttributeTypeOid::OID_SHADOW_FLAG,
                NisAttributeTypeOid::NAME_SHADOW_FLAG,
                NisAttributeTypeOid::DESC_SHADOW_FLAG,
            ),
            self::ia5(
                NisAttributeTypeOid::OID_GECOS,
                NisAttributeTypeOid::NAME_GECOS,
                MatchingRuleOid::OID_CASE_IGNORE_IA5_MATCH,
                true,
                NisAttributeTypeOid::DESC_GECOS,
            ),
            self::ia5(
                NisAttributeTypeOid::OID_HOME_DIRECTORY,
                NisAttributeTypeOid::NAME_HOME_DIRECTORY,
                MatchingRuleOid::OID_CASE_EXACT_IA5_MATCH,
                true,
                NisAttributeTypeOid::DESC_HOME_DIRECTORY,
            ),
            self::ia5(
                NisAttributeTypeOid::OID_LOGIN_SHELL,
                NisAttributeTypeOid::NAME_LOGIN_SHELL,
                MatchingRuleOid::OID_CASE_EXACT_IA5_MATCH,
                true,
                NisAttributeTypeOid::DESC_LOGIN_SHELL,
            ),
            self::ia5(
                NisAttributeTypeOid::OID_MEMBER_UID,
                NisAttributeTypeOid::NAME_MEMBER_UID,
                MatchingRuleOid::OID_CASE_EXACT_IA5_MATCH,
                false,
                NisAttributeTypeOid::DESC_MEMBER_UID,
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
            syntaxOid: SyntaxOid::OID_INTEGER,
            singleValue: true,
            desc: $desc,
        );
    }

    private static function ia5(
        string $oid,
        string $name,
        string $equalityOid,
        bool $singleValue,
        string $desc,
    ): AttributeType {
        return new AttributeType(
            $oid,
            [$name],
            equalityOid: $equalityOid,
            syntaxOid: SyntaxOid::OID_IA5_STRING,
            singleValue: $singleValue,
            desc: $desc,
        );
    }

    /**
     * @return list<ObjectClass>
     */
    private static function objectClasses(): array
    {
        return [
            new ObjectClass(
                NisObjectClassOid::OID_POSIX_ACCOUNT,
                [NisObjectClassOid::NAME_POSIX_ACCOUNT],
                type: ObjectClassType::AuxiliaryClass,
                superClassOids: [ObjectClassOid::OID_TOP],
                must: [
                    AttributeTypeOid::NAME_CN,
                    AttributeTypeOid::NAME_UID,
                    NisAttributeTypeOid::NAME_UID_NUMBER,
                    NisAttributeTypeOid::NAME_GID_NUMBER,
                    NisAttributeTypeOid::NAME_HOME_DIRECTORY,
                ],
                may: [
                    AttributeTypeOid::NAME_USER_PASSWORD,
                    NisAttributeTypeOid::NAME_LOGIN_SHELL,
                    NisAttributeTypeOid::NAME_GECOS,
                    AttributeTypeOid::NAME_DESCRIPTION,
                ],
                desc: NisObjectClassOid::DESC_POSIX_ACCOUNT,
            ),
            new ObjectClass(
                NisObjectClassOid::OID_SHADOW_ACCOUNT,
                [NisObjectClassOid::NAME_SHADOW_ACCOUNT],
                type: ObjectClassType::AuxiliaryClass,
                superClassOids: [ObjectClassOid::OID_TOP],
                must: [AttributeTypeOid::NAME_UID],
                may: [
                    AttributeTypeOid::NAME_USER_PASSWORD,
                    NisAttributeTypeOid::NAME_SHADOW_LAST_CHANGE,
                    NisAttributeTypeOid::NAME_SHADOW_MIN,
                    NisAttributeTypeOid::NAME_SHADOW_MAX,
                    NisAttributeTypeOid::NAME_SHADOW_WARNING,
                    NisAttributeTypeOid::NAME_SHADOW_INACTIVE,
                    NisAttributeTypeOid::NAME_SHADOW_EXPIRE,
                    NisAttributeTypeOid::NAME_SHADOW_FLAG,
                    AttributeTypeOid::NAME_DESCRIPTION,
                ],
                desc: NisObjectClassOid::DESC_SHADOW_ACCOUNT,
            ),
            new ObjectClass(
                NisObjectClassOid::OID_POSIX_GROUP,
                [NisObjectClassOid::NAME_POSIX_GROUP],
                type: ObjectClassType::StructuralClass,
                superClassOids: [ObjectClassOid::OID_TOP],
                must: [
                    AttributeTypeOid::NAME_CN,
                    NisAttributeTypeOid::NAME_GID_NUMBER,
                ],
                may: [
                    AttributeTypeOid::NAME_USER_PASSWORD,
                    NisAttributeTypeOid::NAME_MEMBER_UID,
                    AttributeTypeOid::NAME_DESCRIPTION,
                ],
                desc: NisObjectClassOid::DESC_POSIX_GROUP,
            ),
        ];
    }
}
