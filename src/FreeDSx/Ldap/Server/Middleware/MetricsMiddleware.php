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

namespace FreeDSx\Ldap\Server\Middleware;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Operation\Request\AnonBindRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SaslBindRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Server\Metrics\MetricsRecorderInterface;
use FreeDSx\Ldap\Server\Metrics\Observation\OperationObservation;
use FreeDSx\Ldap\Server\Metrics\Rollup\OperationRollupCoordinator;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Operation\OperationOutcome;
use FreeDSx\Ldap\Server\Operation\OperationResult;

use function microtime;

/**
 * Times each message and records its operation outcome to the metrics recorder.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class MetricsMiddleware implements MiddlewareInterface
{
    /**
     * @param OperationRollupCoordinator|null $rollup Streams each op to the parent so cn=monitor stays fresh on
     *                                                long-lived connections (null under Swoole and when monitor is off).
     */
    public function __construct(
        private MetricsRecorderInterface $recorder,
        private ?OperationRollupCoordinator $rollup = null,
    ) {}

    public function process(
        ServerRequestContext $context,
        MiddlewareHandlerInterface $next,
    ): OperationResult {
        $request = $context->message->getRequest();
        $operation = OperationType::classify($request);
        $startedAt = microtime(true);

        try {
            $result = $next->handle($context);
        } catch (OperationException $e) {
            $this->record(
                $request,
                $operation,
                false,
                microtime(true) - $startedAt,
                $e->getCode(),
            );

            throw $e;
        }

        $this->record(
            $request,
            $operation,
            $result->outcome() === OperationOutcome::Succeeded,
            microtime(true) - $startedAt,
            $result->resultCode(),
        );

        return $result;
    }

    private function record(
        RequestInterface $request,
        OperationType $operation,
        bool $succeeded,
        float $durationSeconds,
        int $resultCode,
    ): void {
        $this->recorder->operationObserved(new OperationObservation(
            $operation,
            $succeeded,
            $durationSeconds,
            $resultCode,
            $this->bindMethod($request),
            $this->searchScope($request),
        ));
        $this->rollup?->flush();
    }

    private function bindMethod(RequestInterface $request): ?string
    {
        return match (true) {
            $request instanceof AnonBindRequest => 'anonymous',
            $request instanceof SaslBindRequest => 'sasl',
            $request instanceof SimpleBindRequest => 'simple',
            default => null,
        };
    }

    private function searchScope(RequestInterface $request): ?string
    {
        if (!$request instanceof SearchRequest) {
            return null;
        }

        return match ($request->getScope()) {
            SearchRequest::SCOPE_BASE_OBJECT => 'base',
            SearchRequest::SCOPE_SINGLE_LEVEL => 'one',
            SearchRequest::SCOPE_WHOLE_SUBTREE => 'sub',
            default => null,
        };
    }
}
