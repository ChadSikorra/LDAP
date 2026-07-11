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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter;

/**
 * A single sidecar leaf a composed filter can be driven from: its sub-select WHERE body and that body's parameters.
 */
final readonly class SidecarLeaf
{
    /**
     * @param list<string> $params
     */
    public function __construct(
        public string $condition,
        public array $params,
    ) {}
}
