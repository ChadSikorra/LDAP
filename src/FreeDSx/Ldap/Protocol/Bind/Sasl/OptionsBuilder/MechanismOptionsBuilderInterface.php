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

namespace FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder;

use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Options\ChallengeOptionsInterface;

/**
 * Builds the options DTO passed to a SASL mechanism's challenge() call for a specific mechanism.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface MechanismOptionsBuilderInterface
{
    /**
     * Build the options for the next challenge() call, or null when no options are needed.
     */
    public function buildOptions(
        ?string $received,
        MechanismName $mechanism,
    ): ?ChallengeOptionsInterface;

}
