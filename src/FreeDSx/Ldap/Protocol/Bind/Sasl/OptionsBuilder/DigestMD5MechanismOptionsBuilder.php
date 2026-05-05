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

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Protocol\Bind\Sasl\UsernameExtractor\SaslUsernameExtractorInterface;
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Options\ChallengeOptionsInterface;
use FreeDSx\Sasl\Options\DigestMD5Options;

/**
 * Builds options for the DIGEST-MD5 SASL mechanism on the server side.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class DigestMD5MechanismOptionsBuilder implements MechanismOptionsBuilderInterface
{
    use RequiresPasswordTrait;

    public function __construct(
        private readonly PasswordAuthenticatableInterface $handler,
        private readonly SaslUsernameExtractorInterface $usernameExtractor,
    ) {
    }

    /**
     * {@inheritDoc}
     *
     * @throws OperationException
     */
    public function buildOptions(
        ?string $received,
        MechanismName $mechanism,
    ): ?ChallengeOptionsInterface {
        if ($received === null) {
            return null;
        }

        $username = $this->usernameExtractor->extractUsername(
            MechanismName::DIGEST_MD5,
            $received,
        );
        $password = $this->requirePassword($this->handler->getPassword(
            $username,
            MechanismName::DIGEST_MD5->value,
        ));

        return (new DigestMD5Options())->setPassword($password);
    }
}
