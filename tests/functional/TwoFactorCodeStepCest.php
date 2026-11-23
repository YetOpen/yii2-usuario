<?php

use Da\User\Form\LoginForm;
use Da\User\Model\User;
use Da\User\Service\TwoFactorEmailCodeGeneratorService;
use Da\User\Service\TwoFactorSmsCodeGeneratorService;
use Da\User\Validator\TwoFactorEmailValidator;
use Da\User\Validator\TwoFactorTextMessageValidator;
use tests\_fixtures\UserFixture;
use yii\helpers\Url;

/**
 * The web login's code step (security/confirm) must only accept the second factor of the
 * user whose credentials were checked at the first step, and an e-mail / SMS code must only
 * be usable by the user it was generated for.
 */
class TwoFactorCodeStepCest
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

    public function testCodeStepIgnoresPostedCredentials(FunctionalTester $I)
    {
        $attacker = $this->enableEmailTwoFactor($I->grabFixture('user', 'user'));
        $victim = $this->enableEmailTwoFactor($I->grabFixture('user', 'seconduser'));

        $I->amGoingTo('reach the code step with my own credentials');
        $this->submitCredentials($I, $attacker->email);
        $I->see('Two factor authentication code');
        $code = $this->grabLastEmailedCode($I);

        $I->amGoingTo('post another user\'s credentials together with my own code');
        $I->submitForm('#LoginForm', [
            'LoginForm[login]' => $victim->email,
            'LoginForm[password]' => 'qwerty',
            'LoginForm[twoFactorAuthenticationCode]' => $code,
        ]);

        $I->expectTo('be signed in as the user of the session credentials, never as the posted one');
        $I->assertNotEquals($victim->id, Yii::$app->user->id);
        $I->assertEquals($attacker->id, Yii::$app->user->id);
    }

    public function testCodeStepAjaxValidationIgnoresPostedCredentials(FunctionalTester $I)
    {
        $attacker = $this->enableEmailTwoFactor($I->grabFixture('user', 'user'));
        $victim = $this->enableEmailTwoFactor($I->grabFixture('user', 'seconduser'));

        $this->submitCredentials($I, $attacker->email);
        $code = $this->grabLastEmailedCode($I);

        $I->amGoingTo('validate via ajax another user\'s credentials with a wrong password');
        $I->sendAjaxPostRequest(Url::to(['/user/security/confirm']), ['LoginForm' => [
            'login' => $victim->email,
            'password' => 'not-the-password',
            'twoFactorAuthenticationCode' => $code,
        ]]);

        $I->expectTo('see the posted credentials ignored: the session ones are valid, so no errors');
        $I->seeResponseCodeIs(200);
        $I->assertSame([], json_decode($I->grabPageSource(), true));
        $I->assertTrue(Yii::$app->user->getIsGuest());
    }

    public function testTwoFactorScenarioOnlyLoadsTheCode(FunctionalTester $I)
    {
        /** @var LoginForm $form */
        $form = Yii::$container->get(LoginForm::class);
        $form->setScenario('2fa');

        $I->assertSame(['twoFactorAuthenticationCode'], $form->safeAttributes());
        $I->assertContains('login', $form->activeAttributes());
        $I->assertContains('password', $form->activeAttributes());
    }

    public function testEmailCodeIsBoundToItsUser(FunctionalTester $I)
    {
        $owner = $this->enableEmailTwoFactor($I->grabFixture('user', 'user'));
        $other = $this->enableEmailTwoFactor($I->grabFixture('user', 'seconduser'));

        $code = Yii::$container->get(TwoFactorEmailCodeGeneratorService::class, [$owner])->run();

        $I->assertFalse((new TwoFactorEmailValidator($other, $code))->validate());
        $I->assertTrue((new TwoFactorEmailValidator($owner, $code))->validate());
    }

    public function testSmsCodeIsBoundToItsUser(FunctionalTester $I)
    {
        $sender = FakeSmsSender::install();
        $owner = $I->grabFixture('user', 'user');
        $owner->updateAttributes(['auth_tf_mobile_phone' => '+390000000001']);
        $other = $I->grabFixture('user', 'seconduser');
        $other->updateAttributes(['auth_tf_mobile_phone' => '+390000000002']);

        $I->assertTrue(Yii::$container->get(TwoFactorSmsCodeGeneratorService::class, [$owner])->run());
        $code = $sender->lastMessage;

        $I->assertFalse((new TwoFactorTextMessageValidator($other, $code))->validate());
        $I->assertTrue((new TwoFactorTextMessageValidator($owner, $code))->validate());
    }

    public function testEmailCodeCannotBeReusedAfterLogin(FunctionalTester $I)
    {
        $user = $this->enableEmailTwoFactor($I->grabFixture('user', 'user'));

        $this->submitCredentials($I, $user->email);
        $code = $this->grabLastEmailedCode($I);
        $I->submitForm('#LoginForm', ['LoginForm[twoFactorAuthenticationCode]' => $code]);
        $I->assertEquals($user->id, Yii::$app->user->id);

        $I->expectTo('find the code spent once the login succeeded');
        $I->assertFalse((new TwoFactorEmailValidator($user, $code))->validate());
    }

    public function testReloadingTheCodeStepDoesNotSendAnotherCode(FunctionalTester $I)
    {
        $user = $this->enableEmailTwoFactor($I->grabFixture('user', 'user'));

        $this->submitCredentials($I, $user->email);
        $code = $this->grabLastEmailedCode($I);
        $I->amOnRoute('/user/security/confirm');
        $I->amOnRoute('/user/security/confirm');

        $I->expectTo('have received a single e-mail, whose code still works');
        $I->assertCount(1, $I->grabSentEmails());
        $I->submitForm('#LoginForm', ['LoginForm[twoFactorAuthenticationCode]' => $code]);
        $I->assertEquals($user->id, Yii::$app->user->id);
    }

    public function testCodeStepSendsANewCodeOnceTheOldOneExpired(FunctionalTester $I)
    {
        $user = $this->enableEmailTwoFactor($I->grabFixture('user', 'user'));

        $this->submitCredentials($I, $user->email);
        Yii::$app->session->set(TwoFactorEmailCodeGeneratorService::SESSION_CODE_TIME, date('Y-m-d H:i:s', time() - 301));
        $I->amOnRoute('/user/security/confirm');

        $I->assertCount(2, $I->grabSentEmails());
    }

    public function testRepeatingTheLoginDoesNotSendAnotherCode(FunctionalTester $I)
    {
        $user = $this->enableEmailTwoFactor($I->grabFixture('user', 'user'));

        $this->submitCredentials($I, $user->email);
        $code = $this->grabLastEmailedCode($I);

        $I->amGoingTo('submit the password again and again, as a flood would');
        $this->submitCredentials($I, $user->email);
        $this->submitCredentials($I, $user->email);

        $I->expectTo('have received a single e-mail, whose code still works');
        $I->assertCount(1, $I->grabSentEmails());
        $I->submitForm('#LoginForm', ['LoginForm[twoFactorAuthenticationCode]' => $code]);
        $I->assertEquals($user->id, Yii::$app->user->id);
    }

    public function testSignedInUserIsSentHomeFromTheCodeSteps(FunctionalTester $I)
    {
        $I->amLoggedInAs($I->grabFixture('user', 'user'));

        foreach (['/user/security/confirm', '/user/security/recovery-code'] as $route) {
            $I->amOnRoute($route);
            $I->seeResponseCodeIs(200);
            $I->dontSee('Forbidden');
            $I->see('Logout');
        }

        $I->sendAjaxPostRequest(Url::to(['/user/security/confirm']), ['LoginForm' => ['twoFactorAuthenticationCode' => '000000']]);
        $I->dontSeeResponseCodeIs(403);
    }

    public function testRememberMeChosenAtTheFirstStepIsKept(FunctionalTester $I)
    {
        $user = $this->enableEmailTwoFactor($I->grabFixture('user', 'user'));

        $this->submitCredentials($I, $user->email, true);
        $I->submitForm('#LoginForm', ['LoginForm[twoFactorAuthenticationCode]' => $this->grabLastEmailedCode($I)]);

        $I->assertEquals($user->id, Yii::$app->user->id);
        $I->seeCookie('_identity');
    }

    public function testWithoutRememberMeNoIdentityCookieIsSet(FunctionalTester $I)
    {
        $user = $this->enableEmailTwoFactor($I->grabFixture('user', 'user'));

        $this->submitCredentials($I, $user->email);
        $I->submitForm('#LoginForm', ['LoginForm[twoFactorAuthenticationCode]' => $this->grabLastEmailedCode($I)]);

        $I->assertEquals($user->id, Yii::$app->user->id);
        $I->dontSeeCookie('_identity');
    }

    public function testCodeStepLocksAfterTooManyWrongCodes(FunctionalTester $I)
    {
        $user = $this->enableEmailTwoFactor($I->grabFixture('user', 'user'));

        $this->submitCredentials($I, $user->email);
        $code = $this->grabLastEmailedCode($I);
        $wrong = $this->wrongCode($code);
        for ($i = 0; $i < 5; $i++) {
            $I->submitForm('#LoginForm', ['LoginForm[twoFactorAuthenticationCode]' => $wrong]);
            $I->dontSee('Too many wrong codes');
        }

        $I->amGoingTo('enter the right code once the attempts are used up');
        $I->submitForm('#LoginForm', ['LoginForm[twoFactorAuthenticationCode]' => $code]);

        $I->see('Too many wrong codes');
        $I->assertTrue(Yii::$app->user->getIsGuest());
    }

    public function testAjaxValidationCountsAsAnAttempt(FunctionalTester $I)
    {
        $user = $this->enableEmailTwoFactor($I->grabFixture('user', 'user'));

        $this->submitCredentials($I, $user->email);
        $code = $this->grabLastEmailedCode($I);
        for ($i = 0; $i < 5; $i++) {
            $I->sendAjaxPostRequest(Url::to(['/user/security/confirm']), ['LoginForm' => ['twoFactorAuthenticationCode' => $this->wrongCode($code)]]);
        }
        $I->sendAjaxPostRequest(Url::to(['/user/security/confirm']), ['LoginForm' => ['twoFactorAuthenticationCode' => $code]]);

        $I->assertStringContainsString('Too many wrong codes', $I->grabPageSource());
    }

    public function testLockIsKeptOnTheUserNotInTheSession(FunctionalTester $I)
    {
        $user = $this->enableEmailTwoFactor($I->grabFixture('user', 'user'));
        $user->updateAttributes(['auth_tf_failed_attempts' => 5, 'auth_tf_last_failed_at' => time()]);

        $I->amGoingTo('start over in a brand new session');
        $this->submitCredentials($I, $user->email);
        $I->submitForm('#LoginForm', ['LoginForm[twoFactorAuthenticationCode]' => $this->grabLastEmailedCode($I)]);

        $I->see('Too many wrong codes');
        $I->assertTrue(Yii::$app->user->getIsGuest());
    }

    public function testLockExpiresAndARightCodeResetsTheCount(FunctionalTester $I)
    {
        $user = $this->enableEmailTwoFactor($I->grabFixture('user', 'user'));
        $user->updateAttributes(['auth_tf_failed_attempts' => 5, 'auth_tf_last_failed_at' => time() - 301]);

        $this->submitCredentials($I, $user->email);
        $I->submitForm('#LoginForm', ['LoginForm[twoFactorAuthenticationCode]' => $this->grabLastEmailedCode($I)]);

        $I->assertEquals($user->id, Yii::$app->user->id);
        $I->seeRecord(User::class, ['id' => $user->id, 'auth_tf_failed_attempts' => 0, 'auth_tf_last_failed_at' => null]);
    }

    public function testApiVerifyLocksAfterTooManyWrongCodes(FunctionalTester $I)
    {
        $user = $this->enableEmailTwoFactor($I->grabFixture('user', 'user'));
        $code = Yii::$container->get(TwoFactorEmailCodeGeneratorService::class, [$user])->run();
        $token = base64_encode(Yii::$app->security->encryptByKey(
            json_encode(['id' => $user->id, 'expire' => time() + 300]),
            Yii::$app->request->cookieValidationKey
        ));
        $url = Url::to(['/user/api/v1/security/verify']);

        for ($i = 0; $i < 5; $i++) {
            $I->sendAjaxPostRequest($url, ['tfa_token' => $token, 'code' => $this->wrongCode($code)]);
            $I->seeResponseCodeIs(401);
        }
        $I->sendAjaxPostRequest($url, ['tfa_token' => $token, 'code' => $code]);

        $I->seeResponseCodeIs(429);
    }

    private function enableEmailTwoFactor(User $user)
    {
        $user->updateAttributes(['auth_tf_enabled' => true, 'auth_tf_type' => 'email']);

        return $user;
    }

    private function submitCredentials(FunctionalTester $I, $login, $rememberMe = false)
    {
        $I->amOnRoute('/user/security/login');
        $I->fillField('#loginform-login', $login);
        $I->fillField('#loginform-password', 'qwerty');
        if ($rememberMe) {
            $I->checkOption('#loginform-rememberme');
        }
        $I->click('Sign in');
    }

    private function grabLastEmailedCode(FunctionalTester $I)
    {
        $body = $I->grabLastSentEmail()->getSymfonyEmail()->getHtmlBody();
        $I->assertSame(1, preg_match('/<b>(\d{6})<\/b>/', $body, $matches), 'No code found in the e-mail');

        return $matches[1];
    }

    private function wrongCode($code)
    {
        return sprintf('%06d', ((int) $code + 1) % 1000000);
    }
}
