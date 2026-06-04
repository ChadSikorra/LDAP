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

namespace FreeDSx\Ldap\Server\Operation;

use FreeDSx\Ldap\Operation\ResultCode;

/**
 * A result conveying only its outcome and result code, with no further detail to carry.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class OperationOutcomeResult implements OperationResult
{
    private function __construct(
        private OperationOutcome $outcome,
        private int $resultCode,
    ) {}

    public static function succeeded(): self
    {
        return new self(
            OperationOutcome::Succeeded,
            ResultCode::SUCCESS,
        );
    }

    public static function failed(int $resultCode = ResultCode::OPERATIONS_ERROR): self
    {
        return new self(
            OperationOutcome::Failed,
            $resultCode,
        );
    }

    public function outcome(): OperationOutcome
    {
        return $this->outcome;
    }

    public function resultCode(): int
    {
        return $this->resultCode;
    }
}
