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

namespace Tests\Support\FreeDSx\Ldap\Middleware;

use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Operation\OperationOutcomeResult;
use FreeDSx\Ldap\Server\Operation\OperationResult;

/**
 * Terminal handler that records its invocation and captures the received context.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class RecordingMiddlewareHandler implements MiddlewareHandlerInterface
{
    public ?ServerRequestContext $received = null;

    public function __construct(
        private readonly CallLog $log,
        private readonly string $label = 'terminal',
    ) {}

    public function handle(ServerRequestContext $context): OperationResult
    {
        $this->received = $context;
        $this->log->record($this->label);

        return OperationOutcomeResult::succeeded();
    }
}
