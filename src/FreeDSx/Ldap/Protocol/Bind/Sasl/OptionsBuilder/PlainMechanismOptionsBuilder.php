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

use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Options\ChallengeOptionsInterface;
use FreeDSx\Sasl\Options\PlainOptions;

/**
 * Builds options for the PLAIN SASL mechanism on the server side.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class PlainMechanismOptionsBuilder implements MechanismOptionsBuilderInterface
{
    public function __construct(private readonly PasswordAuthenticatableInterface $authenticator)
    {
    }

    /**
     * {@inheritDoc}
     */
    public function buildOptions(
        ?string $received,
        MechanismName $mechanism,
    ): ?ChallengeOptionsInterface {
        return (new PlainOptions())->setValidate(
            fn (?string $authzId, string $authcId, string $password): bool =>
                $this->authenticator->verifyPassword($authcId, $password),
        );
    }
}
