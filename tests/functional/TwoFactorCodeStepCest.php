<?php

use Da\User\Form\LoginForm;
use Da\User\Model\User;
use tests\_fixtures\UserFixture;
use yii\helpers\Url;

/**
 * The web login's code step (security/confirm) must only accept the second factor of the
 * user whose credentials were checked at the first step.
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

    private function enableEmailTwoFactor(User $user)
    {
        $user->updateAttributes(['auth_tf_enabled' => true, 'auth_tf_type' => 'email']);

        return $user;
    }

    private function submitCredentials(FunctionalTester $I, $login)
    {
        $I->amOnRoute('/user/security/login');
        $I->fillField('#loginform-login', $login);
        $I->fillField('#loginform-password', 'qwerty');
        $I->click('Sign in');
    }

    private function grabLastEmailedCode(FunctionalTester $I)
    {
        $body = $I->grabLastSentEmail()->getSymfonyEmail()->getHtmlBody();
        $I->assertSame(1, preg_match('/<b>(\d{6})<\/b>/', $body, $matches), 'No code found in the e-mail');

        return $matches[1];
    }
}
