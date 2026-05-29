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

namespace FreeDSx\Ldap\Ldif\Loader;

use Generator;

/**
 * Yields LDIF lines from some source (file, string, database, etc.) for streaming parse.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface LdifLoaderInterface
{
    /**
     * @return Generator<string> LDIF lines without trailing newlines
     */
    public function load(): Generator;
}
