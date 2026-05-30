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

namespace FreeDSx\Ldap\Server\Backend\Write;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteCommand;

/**
 * A backend that can delete an entry together with its whole subtree (Tree-Delete control).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface SubtreeDeleteCapableInterface
{
    /**
     * Delete the entry and every descendant.
     *
     * @param callable(Dn): void $authorize Throws OperationException to deny removal of the given entry.
     * @throws OperationException
     */
    public function deleteSubtree(
        DeleteCommand $command,
        WriteContext $context,
        callable $authorize,
    ): void;
}
