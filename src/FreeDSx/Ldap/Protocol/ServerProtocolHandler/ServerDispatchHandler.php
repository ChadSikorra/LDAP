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

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\AccessControl\OperationTargetDn;
use FreeDSx\Ldap\Server\AccessControl\OperationType;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteCommand;
use FreeDSx\Ldap\Server\Backend\Write\SchemaViolations;
use FreeDSx\Ldap\Server\Backend\Write\SubtreeDeleteCapableInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteCommandFactory;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Backend\Write\WriteOperationDispatcher;
use FreeDSx\Ldap\Server\Operation\CompareOperationResult;
use FreeDSx\Ldap\Server\Operation\OperationResult;
use FreeDSx\Ldap\Server\Operation\WriteOperationResult;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Handles generic requests that are dispatched to the backend.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ServerDispatchHandler implements ServerProtocolHandlerInterface
{
    use MatchedDnAccessFilterTrait;

    private AssertionEvaluator $assertionEvaluator;

    private ReadEntryControlHandler $readEntryControlHandler;

    public function __construct(
        private ServerQueue $queue,
        private LdapBackendInterface $backend,
        private WriteOperationDispatcher $writeDispatcher,
        private AccessControlInterface $accessControl,
        FilterEvaluatorInterface $filterEvaluator,
        Schema $schema,
        private WriteCommandFactory $commandFactory = new WriteCommandFactory(),
        private ResponseFactory $responseFactory = new ResponseFactory(),
        private ?PasswordPolicyContext $passwordPolicyContext = null,
    ) {
        $this->assertionEvaluator = new AssertionEvaluator(
            $filterEvaluator,
            $this->backend,
        );
        $this->readEntryControlHandler = new ReadEntryControlHandler(
            $this->backend,
            $schema,
        );
    }

    /**
     * {@inheritDoc}
     *
     * @throws EncoderException
     */
    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): OperationResult {
        $this->passwordPolicyContext?->clear();
        $schemaViolations = new SchemaViolations();
        $request = $message->getRequest();
        $controls = $message->controls();

        try {
            $target = OperationTargetDn::of($request);
            if ($target !== null) {
                $this->assertionEvaluator->assertSatisfied(
                    $target,
                    $controls,
                );
            }

            if ($request instanceof Request\CompareRequest) {
                return $this->handleCompare(
                    $message,
                    $request,
                );
            }

            return $this->handleWrite(
                $message,
                $request,
                $controls,
                $token,
                $schemaViolations,
            );
        } catch (OperationException $e) {
            return $this->handleFailure(
                $message,
                $e,
                $token,
                $schemaViolations,
            );
        }
    }

    /**
     * @throws OperationException
     * @throws EncoderException
     */
    private function handleCompare(
        LdapMessageRequest $message,
        Request\CompareRequest $request,
    ): OperationResult {
        $match = $this->backend->compare(
            $request->getDn(),
            $request->getFilter(),
        );
        $this->queue->sendMessage($this->responseFactory->getStandardResponse(
            $message,
            $match
                ? ResultCode::COMPARE_TRUE
                : ResultCode::COMPARE_FALSE,
        ));

        return CompareOperationResult::completed(
            $message,
            $match,
        );
    }

    /**
     * @throws OperationException
     * @throws EncoderException
     */
    private function handleWrite(
        LdapMessageRequest $message,
        Request\RequestInterface $request,
        ControlBag $controls,
        TokenInterface $token,
        SchemaViolations $schemaViolations,
    ): OperationResult {
        $preRead = $this->readEntryControlHandler->preReadFor($request, $controls);

        $this->dispatchWrite(
            $request,
            $controls,
            $token,
            $schemaViolations,
        );

        $postRead = $this->readEntryControlHandler->postReadFor($request, $controls);

        $this->queue->sendMessage($this->responseFactory->getStandardResponse(
            $message,
            ResultCode::SUCCESS,
            '',
            null,
            ...$this->successControls($preRead, $postRead),
        ));

        return WriteOperationResult::success(
            $message,
            $schemaViolations,
        );
    }

    /**
     * @throws OperationException
     */
    private function dispatchWrite(
        Request\RequestInterface $request,
        ControlBag $controls,
        TokenInterface $token,
        SchemaViolations $schemaViolations,
    ): void {
        if ($request instanceof Request\DeleteRequest && $controls->has(Control::OID_SUBTREE_DELETE)) {
            $this->handleSubtreeDelete(
                $request,
                $controls,
                $token,
                $schemaViolations,
            );

            return;
        }

        $this->writeDispatcher->dispatch(
            $this->commandFactory->fromRequest($request),
            new WriteContext(
                $token,
                $controls,
                schemaViolations: $schemaViolations,
            ),
        );
    }

    /**
     * @throws OperationException
     */
    private function handleSubtreeDelete(
        Request\DeleteRequest $request,
        ControlBag $controls,
        TokenInterface $token,
        SchemaViolations $schemaViolations,
    ): void {
        if (!$this->backend instanceof SubtreeDeleteCapableInterface) {
            throw new OperationException(
                'The backend does not support subtree deletion.',
                ResultCode::UNWILLING_TO_PERFORM,
            );
        }

        // Permissive by default; lock down by denying the Delete operation on the subtree (per-entry authorization below).
        $this->backend->deleteSubtree(
            new DeleteCommand($request->getDn()),
            new WriteContext(
                $token,
                $controls,
                schemaViolations: $schemaViolations,
            ),
            function (Dn $dn) use ($token): void {
                $this->accessControl->authorizeOperation(
                    OperationType::Delete,
                    $token,
                    $dn,
                );
            },
        );
    }

    /**
     * @throws EncoderException
     */
    private function handleFailure(
        LdapMessageRequest $message,
        OperationException $e,
        TokenInterface $token,
        SchemaViolations $schemaViolations,
    ): OperationResult {
        $errorControl = $this->passwordPolicyControl();
        $this->queue->sendMessage($this->responseFactory->getStandardResponse(
            $message,
            $e->getCode(),
            $e->getMessage(),
            $this->filterMatchedDn(
                $e->getMatchedDn(),
                $token,
                $this->backend,
                $this->accessControl,
            ),
            ...($errorControl === null ? [] : [$errorControl]),
        ));

        return WriteOperationResult::failure(
            $message,
            $e,
            $schemaViolations,
        );
    }

    /**
     * @return Control[]
     */
    private function successControls(
        ?Control $preRead,
        ?Control $postRead,
    ): array {
        return array_values(array_filter([
            $this->passwordPolicyControl(),
            $preRead,
            $postRead,
        ]));
    }

    private function passwordPolicyControl(): ?Control
    {
        $control = $this->passwordPolicyContext?->buildResponseControl();
        $this->passwordPolicyContext?->clear();

        return $control;
    }
}
