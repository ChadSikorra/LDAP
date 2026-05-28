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

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Server\Token\SystemToken;

/**
 * Replays a sequence of client write requests against a backend as system-initiated operations.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class WriteRequestReplayer
{
    private readonly WriteOperationDispatcher $dispatcher;

    /**
     * @param WriteHandlerInterface[] $writeHandlers Additional handlers tried before the backend.
     */
    public function __construct(
        WriteHandlerInterface $backend,
        array $writeHandlers = [],
        private readonly WriteCommandFactory $commandFactory = new WriteCommandFactory(),
    ) {
        $writeHandlers[] = $backend;
        $this->dispatcher = new WriteOperationDispatcher(...$writeHandlers);
    }

    /**
     * @param iterable<RequestInterface> $requests
     * @throws OperationException
     */
    public function apply(iterable $requests): void
    {
        $context = WriteContext::system(
            new SystemToken(),
            new ControlBag(),
        );

        foreach ($requests as $request) {
            $this->dispatcher->dispatch(
                $this->commandFactory->fromRequest($request),
                $context,
            );
        }
    }
}
