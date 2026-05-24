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

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashService;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Server\PasswordPolicy\Attempt\PasswordModifyAttempt;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\PasswordPolicyChangeGuard;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;

/**
 * Enforces password policy on a plain ldapmodify of userPassword, delegating the write to a decorated handler.
 */
final readonly class PasswordPolicyWriteHandler implements WriteHandlerInterface
{
    /**
     * Change types that set a new password value.
     */
    private const SET_TYPES = [
        Change::TYPE_ADD,
        Change::TYPE_REPLACE,
    ];

    public function __construct(
        private LdapBackendInterface&WriteHandlerInterface $backend,
        private PasswordPolicyChangeGuard $changeGuard,
        private SystemChangeWriter $systemChangeWriter,
        private PasswordHashService $hashService = new PasswordHashService(),
    ) {}

    public function supports(WriteRequestInterface $request): bool
    {
        return $request instanceof UpdateCommand
            && $this->userPasswordValues($request, self::SET_TYPES) !== [];
    }

    /**
     * @throws OperationException
     */
    public function handle(
        WriteRequestInterface $request,
        WriteContext $context,
    ): void {
        if (!$request instanceof UpdateCommand) {
            $this->backend->handle(
                $request,
                $context,
            );

            return;
        }

        $newPasswords = $this->userPasswordValues($request, self::SET_TYPES);
        $entry = $this->backend->get($request->dn);
        if ($newPasswords === [] || $entry === null) {
            $this->backend->handle(
                $request,
                $context,
            );

            return;
        }

        $oldPassword = $this->userPasswordValues($request, [Change::TYPE_DELETE])[0] ?? null;
        $isSelf = $this->isSelf(
            $context,
            $request->dn,
        );

        // Every value being set must satisfy policy; otherwise a weak value could ride along behind a valid one
        // each value is recorded in history so none can be reused after a multi-valued set.
        $attempts = array_map(
            fn(string $newPassword): PasswordModifyAttempt => new PasswordModifyAttempt(
                target: $entry,
                newPassword: $newPassword,
                hashedNewPassword: $newPassword,
                oldPassword: $oldPassword,
                isSelf: $isSelf,
                passwordIsCleartext: !$this->hashService->isHashed($newPassword),
            ),
            $newPasswords,
        );
        $deltas = $this->changeGuard->enforceAll($attempts);

        $this->backend->handle(
            $request,
            $context,
        );
        $this->systemChangeWriter->write(
            $request->dn,
            $deltas,
        );

        // A successful self-change satisfies any pwdReset requirement. no re-bind needed.
        $token = $context->getToken();
        if ($isSelf && $token instanceof AuthenticatedTokenInterface) {
            $token->clearMustChangePassword();
        }
    }

    /**
     * @param list<int> $types
     * @return list<string>
     */
    private function userPasswordValues(
        UpdateCommand $command,
        array $types,
    ): array {
        $values = [];
        foreach ($command->changes as $change) {
            if (!$this->isUserPasswordChange($change)) {
                continue;
            }
            if (!in_array($change->getType(), $types, true)) {
                continue;
            }

            foreach ($change->getAttribute()->getValues() as $value) {
                $values[] = $value;
            }
        }

        return $values;
    }

    private function isUserPasswordChange(Change $change): bool
    {
        return strcasecmp(
            $change->getAttribute()->getName(),
            AttributeTypeOid::NAME_USER_PASSWORD,
        ) === 0;
    }

    private function isSelf(
        WriteContext $context,
        Dn $targetDn,
    ): bool {
        $boundDn = $context->getBoundDn();

        return $boundDn !== null
            && (new Dn($boundDn))->normalize()->toString() === $targetDn->normalize()->toString();
    }
}
