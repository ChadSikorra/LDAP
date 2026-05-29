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

namespace FreeDSx\Ldap\Server\Backend\Storage\Export;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Search\Filter\FilterInterface;

/**
 * Options for {@see DirectoryDumper}. Optional filter and subtree restriction.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class DumpOptions
{
    private ?FilterInterface $filter = null;

    private ?Dn $baseDn = null;

    public function getFilter(): ?FilterInterface
    {
        return $this->filter;
    }

    public function setFilter(?FilterInterface $filter): self
    {
        $this->filter = $filter;

        return $this;
    }

    public function getBaseDn(): ?Dn
    {
        return $this->baseDn;
    }

    public function setBaseDn(?Dn $baseDn): self
    {
        $this->baseDn = $baseDn;

        return $this;
    }
}
