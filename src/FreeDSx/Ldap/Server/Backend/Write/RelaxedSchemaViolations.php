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

use FreeDSx\Ldap\Exception\OperationException;

/**
 * Request-scoped record of schema violations allowed under Lenient validation.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class RelaxedSchemaViolations
{
    /**
     * @var OperationException[]
     */
    private array $violations = [];

    public function record(OperationException $violation): void
    {
        $this->violations[] = $violation;
    }

    /**
     * @return OperationException[]
     */
    public function all(): array
    {
        return $this->violations;
    }
}
