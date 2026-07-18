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

use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;

/**
 * Records before/after markers around the next handler for ordering assertions.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class RecordingMiddleware implements MiddlewareInterface
{
    public function __construct(
        private CallLog $log,
        private string $label,
    ) {}

    public function process(
        ServerRequestContext $context,
        MiddlewareHandlerInterface $next,
    ): ResponseStream {
        $this->log->record('before:' . $this->label);
        $result = $next->handle($context);
        $this->log->record('after:' . $this->label);

        return $result;
    }
}
