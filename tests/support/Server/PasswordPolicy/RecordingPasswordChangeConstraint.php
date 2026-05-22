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

namespace Tests\Support\FreeDSx\Ldap\Server\PasswordPolicy;

use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\PasswordChangeAttempt;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\PasswordChangeConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\PasswordPolicyOutcome;

/**
 * Test double that records each invocation and returns a configurable outcome.
 */
final class RecordingPasswordChangeConstraint implements PasswordChangeConstraint
{
    /**
     * @var list<PasswordChangeAttempt>
     */
    public array $invocations = [];

    public function __construct(private readonly ?PasswordPolicyOutcome $outcome = null) {}

    public function check(PasswordChangeAttempt $attempt): ?PasswordPolicyOutcome
    {
        $this->invocations[] = $attempt;

        return $this->outcome;
    }
}
