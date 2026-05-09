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

use FreeDSx\Ldap\Server\Backend\Write\Command\AddCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\MoveCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;

/**
 * Splits WriteHandlerInterface::handle() into four typed methods (add/delete/update/move) for WritableLdapBackendInterface.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait WritableBackendTrait
{
    public function supports(WriteRequestInterface $request): bool
    {
        return $request instanceof AddCommand
            || $request instanceof DeleteCommand
            || $request instanceof UpdateCommand
            || $request instanceof MoveCommand;
    }

    public function handle(
        WriteRequestInterface $request,
        WriteContext $context,
    ): void {
        if ($request instanceof AddCommand) {
            $this->add(
                $request,
                $context,
            );
        } elseif ($request instanceof DeleteCommand) {
            $this->delete(
                $request,
                $context,
            );
        } elseif ($request instanceof UpdateCommand) {
            $this->update(
                $request,
                $context,
            );
        } elseif ($request instanceof MoveCommand) {
            $this->move(
                $request,
                $context,
            );
        }
    }

    abstract public function add(
        AddCommand $command,
        WriteContext $context,
    ): void;

    abstract public function delete(
        DeleteCommand $command,
        WriteContext $context,
    ): void;

    abstract public function update(
        UpdateCommand $command,
        WriteContext $context,
    ): void;

    abstract public function move(
        MoveCommand $command,
        WriteContext $context,
    ): void;
}
