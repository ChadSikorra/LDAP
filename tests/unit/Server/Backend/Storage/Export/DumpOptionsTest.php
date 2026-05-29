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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Export;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\Storage\Export\DumpOptions;
use PHPUnit\Framework\TestCase;

final class DumpOptionsTest extends TestCase
{
    public function test_defaults_filter_and_base_dn_to_null(): void
    {
        $options = new DumpOptions();

        self::assertNull($options->getFilter());
        self::assertNull($options->getBaseDn());
    }

    public function test_filter_round_trips_through_setter(): void
    {
        $filter = Filters::equal('objectClass', 'person');

        $options = (new DumpOptions())->setFilter($filter);

        self::assertSame(
            $filter,
            $options->getFilter(),
        );
    }

    public function test_base_dn_round_trips_through_setter(): void
    {
        $base = new Dn('ou=people,dc=foo,dc=bar');

        $options = (new DumpOptions())->setBaseDn($base);

        self::assertSame(
            $base,
            $options->getBaseDn(),
        );
    }

    public function test_setters_return_self_for_fluent_chaining(): void
    {
        $options = new DumpOptions();

        self::assertSame(
            $options,
            $options->setFilter(null),
        );
        self::assertSame(
            $options,
            $options->setBaseDn(null),
        );
    }
}
