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

namespace FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;

trait ServerCriticalControlTrait
{
    /**
     * OIDs of controls this handler supports.
     *
     * @return string[]
     */
    private function supportedControls(): array
    {
        return [];
    }

    /**
     * Throws if any critical control in $controls is unsupported by this handler.
     *
     * @throws OperationException
     */
    private function assertNoCriticalUnsupportedControls(ControlBag $controls): void
    {
        $supported = $this->supportedControls();

        foreach ($controls as $control) {
            if (!$control->getCriticality()) {
                continue;
            }

            if (!in_array($control->getTypeOid(), $supported, true)) {
                throw new OperationException(
                    sprintf('Critical control %s is not supported.', $control->getTypeOid()),
                    ResultCode::UNAVAILABLE_CRITICAL_EXTENSION,
                );
            }
        }
    }
}
