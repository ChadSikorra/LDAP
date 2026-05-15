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

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Schema\Definition\ObjectClassOid;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use FreeDSx\Ldap\ServerOptions;

/**
 * Returns the full RFC 4512 subschema entry from the active schema registry.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerSubschemaHandler implements ServerProtocolHandlerInterface
{
    use ServerCriticalControlTrait;

    public function __construct(
        private readonly ServerOptions $options,
        private readonly ServerQueue $queue,
    ) {}

    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): void {
        $this->assertNoCriticalUnsupportedControls($message->controls());
        $schemaDn = $this->options->getSubschemaEntry();
        $rdn = $schemaDn->getRdn();
        $schema = $this->options->getSchema();

        $entry = Entry::fromArray(
            $schemaDn->toString(),
            array_filter([
                AttributeTypeOid::NAME_OBJECT_CLASS => [
                    ObjectClassOid::NAME_TOP,
                    ObjectClassOid::NAME_SUBSCHEMA,
                ],
                $rdn->getName() => [$rdn->getValue()],
                AttributeTypeOid::NAME_ATTRIBUTE_TYPES => array_map(
                    fn($at) => $at->toDescriptionString(),
                    $schema->getAttributeTypes(),
                ),
                AttributeTypeOid::NAME_OBJECT_CLASSES => array_map(
                    fn($oc) => $oc->toDescriptionString(),
                    $schema->getObjectClasses(),
                ),
                AttributeTypeOid::NAME_MATCHING_RULES => array_map(
                    fn($mr) => $mr->toDescriptionString(),
                    $schema->getMatchingRules(),
                ),
                AttributeTypeOid::NAME_LDAP_SYNTAXES => array_map(
                    fn($ls) => $ls->toDescriptionString(),
                    $schema->getLdapSyntaxes(),
                ),
                AttributeTypeOid::NAME_MATCHING_RULE_USE => $this->buildMatchingRuleUse($schema),
            ]),
        );

        $this->queue->sendMessage(
            new LdapMessageResponse(
                $message->getMessageId(),
                new SearchResultEntry($entry),
            ),
            new LdapMessageResponse(
                $message->getMessageId(),
                new SearchResultDone(ResultCode::SUCCESS),
            ),
        );
    }

    /**
     * @return list<string>
     */
    private function buildMatchingRuleUse(Schema $schema): array
    {
        $ruleToAttrs = [];
        foreach ($schema->getAttributeTypes() as $attrType) {
            $name = $attrType->names[0] ?? $attrType->oid;

            if ($attrType->equalityOid !== null) {
                $ruleToAttrs[$attrType->equalityOid][] = $name;
            }

            if ($attrType->orderingOid !== null) {
                $ruleToAttrs[$attrType->orderingOid][] = $name;
            }

            if ($attrType->substringOid !== null) {
                $ruleToAttrs[$attrType->substringOid][] = $name;
            }
        }

        $use = [];
        foreach ($ruleToAttrs as $ruleOid => $attrNames) {
            $rule = $schema->getMatchingRule($ruleOid);
            if ($rule === null) {
                continue;
            }

            $use[] = $rule->toMatchingRuleUseString($attrNames);
        }

        return $use;
    }
}
