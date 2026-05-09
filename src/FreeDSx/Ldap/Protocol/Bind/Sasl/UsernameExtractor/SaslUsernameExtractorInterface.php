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

namespace FreeDSx\Ldap\Protocol\Bind\Sasl\UsernameExtractor;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Sasl\Mechanism\MechanismName;

/**
 * Extracts a username from raw SASL credential bytes for a specific set of mechanisms.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface SaslUsernameExtractorInterface
{
    /**
     * Extract the username from raw SASL credential bytes for the given mechanism.
     *
     * @throws OperationException if the username cannot be extracted from the credentials.
     */
    public function extractUsername(MechanismName $mechanism, string $credentials): string;
}
