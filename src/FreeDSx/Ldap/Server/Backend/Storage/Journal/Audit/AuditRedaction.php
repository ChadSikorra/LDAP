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

namespace FreeDSx\Ldap\Server\Backend\Storage\Journal\Audit;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;

/**
 * Drops sensitive attributes from a pre-image before it leaves the server to an audit sink.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class AuditRedaction
{
    /**
     * @var list<string> excluded attribute names, lower-cased for case-insensitive matching
     */
    private array $excluded;

    /**
     * @param list<string> $attributes
     */
    public function __construct(array $attributes)
    {
        $this->excluded = array_values(array_map(
            strtolower(...),
            $attributes,
        ));
    }

    /**
     * Excludes the attributes that carry password material: userPassword and the pwdHistory record.
     */
    public static function default(): self
    {
        return new self([
            AttributeTypeOid::NAME_USER_PASSWORD,
            PasswordPolicyOid::NAME_PWD_HISTORY,
        ]);
    }

    /**
     * The entry's attributes as a map, with excluded attributes removed. Matching is on the base
     * attribute name so an option (e.g. userPassword;binary) cannot slip a secret past redaction.
     *
     * @return array<string, list<string>>
     */
    public function apply(Entry $entry): array
    {
        $attributes = [];

        foreach ($entry->getAttributes() as $attribute) {
            if (in_array(strtolower($attribute->getName()), $this->excluded, true)) {
                continue;
            }

            $attributes[$attribute->getDescription()] = array_values($attribute->getValues());
        }

        return $attributes;
    }
}
