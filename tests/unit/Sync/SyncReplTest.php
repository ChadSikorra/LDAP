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

namespace Tests\Unit\FreeDSx\Ldap\Sync;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\Sync\SyncDoneControl;
use FreeDSx\Ldap\Control\Sync\SyncRequestControl;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Request\SyncRequest;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Sync\Result\SyncEntryResult;
use FreeDSx\Ldap\Sync\Result\SyncIdSetResult;
use FreeDSx\Ldap\Sync\Result\SyncReferralResult;
use FreeDSx\Ldap\Sync\Session;
use FreeDSx\Ldap\Sync\SyncRepl;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class SyncReplTest extends TestCase
{
    private SyncRepl $subject;

    private LdapClient&MockObject $mockClient;

    protected function setUp(): void
    {
        $this->mockClient = $this->createMock(LdapClient::class);

        $this->subject = new SyncRepl($this->mockClient);
    }

    public function test_it_should_poll_for_changes(): void
    {
        $this->mockClient
            ->expects(self::once())
            ->method('sendAndReceive')
            ->with(
                self::anything(),
                self::callback(
                    fn(SyncRequestControl $control) => $control->getMode() === SyncRequestControl::MODE_REFRESH_ONLY,
                ),
                self::anything(),
            )
            ->willReturn(new LdapMessageResponse(
                1,
                new SearchResultDone(0),
                new SyncDoneControl('foo'),
            ));

        $this->subject->poll();
    }

    public function test_it_should_listen_for_changes(): void
    {
        $this->mockClient
            ->expects(self::once())
            ->method('sendAndReceive')
            ->with(
                self::anything(),
                self::callback(
                    fn(SyncRequestControl $control) => $control->getMode() === SyncRequestControl::MODE_REFRESH_AND_PERSIST,
                ),
                self::anything(),
            )
            ->willReturn(new LdapMessageResponse(
                1,
                new SearchResultDone(0),
                new SyncDoneControl('foo'),
            ));

        $this->subject->listen();
    }

    public function test_it_should_use_a_filter_if_specified(): void
    {
        $this->subject->useFilter(Filters::present('foo'));

        $this->mockClient
            ->expects(self::once())
            ->method('sendAndReceive')
            ->with(
                self::callback(
                    fn(SyncRequest $request)
                        => $request->getFilter()->toString() === Filters::present('foo')->toString(),
                ),
                self::anything(),
                self::anything(),
            )->willReturn(new LdapMessageResponse(
                1,
                new SearchResultDone(0),
                new SyncDoneControl('foo'),
            ));

        $this->subject->poll();
    }

    public function test_it_should_use_added_controls_if_specified(): void
    {
        $control = new Control('foo');

        $this->subject
            ->controls()
            ->add($control);

        $this->mockClient
            ->expects(self::once())
            ->method('sendAndReceive')
            ->with(
                self::anything(),
                self::anything(),
                self::anything(),
                $control,
            )->willReturn(new LdapMessageResponse(
                1,
                new SearchResultDone(0),
                new SyncDoneControl('foo'),
            ));

        $this->subject->poll();
    }

    public function test_it_should_use_the_cookie_if_specified(): void
    {
        $this->subject->useCookie('tasty');

        $this->mockClient
            ->expects(self::once())
            ->method('sendAndReceive')
            ->with(
                self::anything(),
                self::callback(
                    fn(SyncRequestControl $control) => $control->getCookie() === 'tasty',
                ),
                self::anything(),
            )->willReturn(new LdapMessageResponse(
                1,
                new SearchResultDone(0),
                new SyncDoneControl('foo'),
            ));

        $this->subject->poll();
    }

    public function test_it_should_use_the_entry_handler_specified(): void
    {
        $handler = fn(SyncEntryResult $result) => $result->getEntry();

        $this->mockClient
            ->expects(self::once())
            ->method('sendAndReceive')
            ->with(
                self::callback(
                    fn(SyncRequest $request) => $request->getEntryHandler() === $handler,
                ),
                self::anything(),
                self::anything(),
            )->willReturn(new LdapMessageResponse(
                1,
                new SearchResultDone(0),
                new SyncDoneControl('foo'),
            ));

        $this->subject->poll($handler);
    }

    public function test_it_should_use_the_referral_handler_specified(): void
    {
        $handler = fn(SyncReferralResult $result) => $result->getReferrals();

        $this->subject->useReferralHandler($handler);

        $this->mockClient
            ->expects(self::once())
            ->method('sendAndReceive')
            ->with(
                self::callback(
                    fn(SyncRequest $request) => $request->getReferralHandler() === $handler,
                ),
                self::anything(),
                self::anything(),
            )->willReturn(new LdapMessageResponse(
                1,
                new SearchResultDone(0),
                new SyncDoneControl('foo'),
            ));

        $this->subject->poll();
    }

    public function test_it_should_use_the_idSet_handler_specified(): void
    {
        $handler = fn(SyncIdSetResult $result) => $result->getEntryUuids();

        $this->subject->useIdSetHandler($handler);

        $this->mockClient
            ->expects(self::once())
            ->method('sendAndReceive')
            ->with(
                self::callback(
                    fn(SyncRequest $request) => $request->getIdSetHandler() === $handler,
                ),
                self::anything(),
                self::anything(),
            )->willReturn(new LdapMessageResponse(
                1,
                new SearchResultDone(0),
                new SyncDoneControl('foo'),
            ));

        $this->subject->poll();
    }

    public function test_it_should_use_the_refresh_done_handler_specified(): void
    {
        $handler = fn(Session $session) => $session->getCookie();

        $this->subject->useRefreshDoneHandler($handler);

        $this->mockClient
            ->expects(self::once())
            ->method('sendAndReceive')
            ->with(
                self::callback(
                    fn(SyncRequest $request) => $request->getRefreshDoneHandler() === $handler,
                ),
                self::anything(),
                self::anything(),
            )->willReturn(new LdapMessageResponse(
                1,
                new SearchResultDone(0),
                new SyncDoneControl('foo'),
            ));

        $this->subject->poll();
    }

    public function test_it_tracks_the_latest_cookie_and_exposes_it(): void
    {
        $this->mockClient
            ->method('sendAndReceive')
            ->willReturnCallback(function (SyncRequest $request): LdapMessageResponse {
                // Simulate the protocol handler delivering a fresh cookie mid-sync.
                $cookieHandler = $request->getCookieHandler();
                self::assertNotNull($cookieHandler);
                $cookieHandler('fresh-cookie');

                return new LdapMessageResponse(
                    1,
                    new SearchResultDone(0),
                    new SyncDoneControl('fresh-cookie'),
                );
            });

        $this->subject->poll();

        self::assertSame(
            'fresh-cookie',
            $this->subject->getCookie(),
        );
    }

    public function test_it_forwards_cookie_updates_to_a_user_cookie_handler(): void
    {
        $seen = null;
        $this->subject->useCookieHandler(function (?string $cookie) use (&$seen): void {
            $seen = $cookie;
        });

        $this->mockClient
            ->method('sendAndReceive')
            ->willReturnCallback(function (SyncRequest $request): LdapMessageResponse {
                $cookieHandler = $request->getCookieHandler();
                self::assertNotNull($cookieHandler);
                $cookieHandler('handed-over');

                return new LdapMessageResponse(
                    1,
                    new SearchResultDone(0),
                    new SyncDoneControl('handed-over'),
                );
            });

        $this->subject->poll();

        self::assertSame(
            'handed-over',
            $seen,
        );
        self::assertSame(
            'handed-over',
            $this->subject->getCookie(),
        );
    }

    public function test_it_should_use_the_continue_strategy_if_specified(): void
    {
        $this->subject->useContinueOnCancel();

        self::assertSame(
            SearchRequest::CANCEL_CONTINUE,
            $this->subject
                ->request()
                ->getCancelStrategy(),
        );
    }
}
