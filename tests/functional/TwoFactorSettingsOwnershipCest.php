<?php

use Da\User\Model\User;
use tests\_fixtures\UserFixture;

/**
 * The 2FA settings actions take the user id from the request: a signed-in user must only
 * be able to act on their own account.
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

        $I->amOnRoute('/user/settings/two-factor-mobile-phone', ['id' => $victim->id, 'mobilephone' => '+390000000666']);

        $I->seeResponseCodeIs(403);
        $I->seeRecord(User::class, ['id' => $victim->id, 'auth_tf_mobile_phone' => '+390000000002']);
        $I->assertNull($sender->lastNumber, 'No code must be sent to the new number');
    }

    public function testCannotEnableTwoFactorOnAnotherUser(FunctionalTester $I)
    {
        $me = $I->grabFixture('user', 'user');
        $victim = $I->grabFixture('user', 'seconduser');
        $I->amLoggedInAs($me);

        $I->amOnRoute('/user/settings/two-factor-enable', ['id' => $victim->id, 'choice' => 'email', 'code' => '000000']);

        $I->seeResponseCodeIs(403);
        $I->seeRecord(User::class, ['id' => $victim->id, 'auth_tf_enabled' => 0]);
    }

    public function testCanStillActOnOwnAccount(FunctionalTester $I)
    {
        $me = $I->grabFixture('user', 'user');
        $I->amLoggedInAs($me);

        $I->amOnRoute('/user/settings/two-factor-enable', ['id' => $me->id, 'choice' => 'email', 'code' => '000000']);
        $I->seeResponseCodeIs(200);
        $I->assertFalse(json_decode($I->grabPageSource(), true)['success']);

        $I->amOnRoute('/user/settings/two-factor-mobile-phone', ['id' => $me->id, 'mobilephone' => $me->auth_tf_mobile_phone]);
        $I->seeResponseCodeIs(200);
        $I->assertTrue(json_decode($I->grabPageSource(), true)['success']);
    }
}
