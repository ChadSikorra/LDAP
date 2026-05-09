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
use FreeDSx\Sasl\Options\CramMD5Options;

/**
 * Builds options for the CRAM-MD5 SASL mechanism on the server side.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class CramMD5MechanismOptionsBuilder implements MechanismOptionsBuilderInterface
{
    use RequiresPasswordTrait;

    public function __construct(private readonly PasswordAuthenticatableInterface $handler) {}

    /**
     * {@inheritDoc}
     */
    public function buildOptions(
        ?string $received,
        MechanismName $mechanism,
    ): ?ChallengeOptionsInterface {
        if ($received === null) {
            return null;
        }

        return (new CramMD5Options())->setPasswordCallback(
            function (string $username, string $challenge): string {
                $password = $this->requirePassword($this->handler->getPassword(
                    $username,
                    MechanismName::CRAM_MD5,
                ));

                return hash_hmac(
                    'md5',
                    $challenge,
                    $password,
                );
            },
        );
    }
}
