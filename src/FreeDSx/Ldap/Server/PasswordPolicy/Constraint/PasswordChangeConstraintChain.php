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

namespace FreeDSx\Ldap\Server\PasswordPolicy\Constraint;

use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyOutcome;

/**
 * Ordered pipeline of {@see PasswordChangeConstraint}s; the first violation short-circuits evaluation.
 */
final readonly class PasswordChangeConstraintChain
{
    /**
     * @param list<PasswordChangeConstraint> $constraints
     */
    public function __construct(private array $constraints) {}

    public function evaluate(PasswordChangeAttempt $attempt): ?PasswordPolicyOutcome
    {
        foreach ($this->constraints as $constraint) {
            $outcome = $constraint->check($attempt);
            if ($outcome !== null) {
                return $outcome;
            }
        }

        return null;
    }
}
