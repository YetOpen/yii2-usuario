<?php

use Da\User\Model\User;
use tests\_fixtures\UserFixture;
use yii\helpers\Url;

/**
 * The 2FA settings actions take the user id from the request: a signed-in user must only
 * be able to act on their own account, and only through a POST (CSRF-checked) request.
 */
class TwoFactorSettingsOwnershipCest
{
    public function _before(FunctionalTester $I)
    {
        $I->haveFixtures(['user' => UserFixture::class]);
        Yii::$app->getModule('user')->enableTwoFactorAuthentication = true;
    }

    public function _after(FunctionalTester $I)
    {
        Yii::$app->getModule('user')->enableTwoFactorAuthentication = false;
    }

    public function testCannotChangeAnotherUsersMobilePhone(FunctionalTester $I)
    {
        $me = $I->grabFixture('user', 'user');
        $victim = $I->grabFixture('user', 'seconduser');
        $victim->updateAttributes(['auth_tf_mobile_phone' => '+390000000002']);
        $sender = FakeSmsSender::install();
        $I->amLoggedInAs($me);

        $this->setMobilePhone($I, $victim->id, '+390000000666');

        $I->seeResponseCodeIs(403);
        $I->seeRecord(User::class, ['id' => $victim->id, 'auth_tf_mobile_phone' => '+390000000002']);
        $I->assertNull($sender->lastNumber, 'No code must be sent to the new number');
    }

    public function testCannotEnableTwoFactorOnAnotherUser(FunctionalTester $I)
    {
        $me = $I->grabFixture('user', 'user');
        $victim = $I->grabFixture('user', 'seconduser');
        $I->amLoggedInAs($me);

        $this->enable($I, $victim->id, 'email', '000000');

        $I->seeResponseCodeIs(403);
        $I->seeRecord(User::class, ['id' => $victim->id, 'auth_tf_enabled' => 0]);
    }

    public function testMobilePhoneCannotBeChangedWithAGetRequest(FunctionalTester $I)
    {
        $me = $I->grabFixture('user', 'user');
        $me->updateAttributes(['auth_tf_mobile_phone' => '+390000000001']);
        $sender = FakeSmsSender::install();
        $I->amLoggedInAs($me);

        $I->amGoingTo('change my number with a GET, as a cross-site link or <img> would');
        $I->amOnRoute('/user/settings/two-factor-mobile-phone', ['id' => $me->id, 'mobilephone' => '+390000000666']);

        $I->seeResponseCodeIs(405);
        $I->seeRecord(User::class, ['id' => $me->id, 'auth_tf_mobile_phone' => '+390000000001']);
        $I->assertNull($sender->lastNumber);
    }

    public function testTwoFactorCannotBeEnabledWithAGetRequest(FunctionalTester $I)
    {
        $me = $I->grabFixture('user', 'user');
        $I->amLoggedInAs($me);

        $I->amOnRoute('/user/settings/two-factor-enable', ['id' => $me->id, 'choice' => 'email', 'code' => '000000']);

        $I->seeResponseCodeIs(405);
    }

    public function testMobilePhoneCannotBeChangedWhileTwoFactorIsEnabled(FunctionalTester $I)
    {
        $me = $I->grabFixture('user', 'user');
        $me->updateAttributes([
            'auth_tf_enabled' => true,
            'auth_tf_type' => 'sms',
            'auth_tf_mobile_phone' => '+390000000001',
        ]);
        $sender = FakeSmsSender::install();
        $I->amLoggedInAs($me);

        $I->amGoingTo('move the SMS codes of my active 2FA to another number');
        $this->setMobilePhone($I, $me->id, '+390000000666');

        $I->expectTo('see the number unchanged: it can only be set while enabling 2FA');
        $I->seeResponseCodeIs(200);
        $I->assertFalse(json_decode($I->grabPageSource(), true)['success']);
        $I->seeRecord(User::class, ['id' => $me->id, 'auth_tf_mobile_phone' => '+390000000001']);
        $I->assertNull($sender->lastNumber);
    }

    public function testCanStillActOnOwnAccount(FunctionalTester $I)
    {
        $me = $I->grabFixture('user', 'user');
        $sender = FakeSmsSender::install();
        $I->amLoggedInAs($me);

        $this->enable($I, $me->id, 'email', '000000');
        $I->seeResponseCodeIs(200);
        $I->assertFalse(json_decode($I->grabPageSource(), true)['success']);

        $this->setMobilePhone($I, $me->id, '+390000000003');
        $I->seeResponseCodeIs(200);
        $I->assertTrue(json_decode($I->grabPageSource(), true)['success']);
        $I->seeRecord(User::class, ['id' => $me->id, 'auth_tf_mobile_phone' => '+390000000003']);
        $I->assertSame('+390000000003', $sender->lastNumber);
    }

    private function setMobilePhone(FunctionalTester $I, $id, $mobilePhone)
    {
        $I->sendAjaxPostRequest(
            Url::to(['/user/settings/two-factor-mobile-phone', 'id' => $id]),
            ['mobilephone' => $mobilePhone]
        );
    }

    private function enable(FunctionalTester $I, $id, $choice, $code)
    {
        $I->sendAjaxPostRequest(
            Url::to(['/user/settings/two-factor-enable', 'id' => $id]),
            ['choice' => $choice, 'code' => $code]
        );
    }
}
