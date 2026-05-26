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

use FreeDSx\Ldap\Server\Logging\OperationAuditor;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * A result that carries audit-specific detail beyond its coarse outcome.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface AuditableResult extends OperationResult
{
    public function record(
        OperationAuditor $auditor,
        TokenInterface $token,
    ): void;
}
