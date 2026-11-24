<?php

/**
 * @var Codeception\Scenario
 */

use Da\User\Form\SettingsForm;
use Da\User\Model\User;
use tests\_fixtures\ProfileFixture;
use tests\_fixtures\UserFixture;
use yii\base\Event;
use yii\base\ModelEvent;

$I = new FunctionalTester($scenario);
$I->wantTo('ensure that a handler of EVENT_PASSWORD_CHANGE_ALLOWED can forbid a password change from Account');
$I->haveFixtures(['user' => UserFixture::className(), 'profile' => ProfileFixture::className()]);

$user = $I->grabFixture('user', 'user');
$I->amLoggedInAs($user);
$message = "Your password is managed by your organisation's directory and cannot be changed here.";

$I->amGoingTo('check that without handlers the password field is shown');
$I->amOnRoute('/user/settings/account');
$I->seeElement('#settingsform-new_password');
$I->dontSee($message);

$handler = function (ModelEvent $event) {
    $event->isValid = false;
};
Event::on(SettingsForm::class, SettingsForm::EVENT_PASSWORD_CHANGE_ALLOWED, $handler);

try {
    $I->amGoingTo('check that a refused change hides the field');
    $I->amOnRoute('/user/settings/account');
    $I->dontSeeElement('#settingsform-new_password');
    $I->see($message);

    $I->amGoingTo('check that a crafted POST carrying new_password is rejected');
    $passwordHash = $user->password_hash;
    /** @var SettingsForm $form */
    $form = Yii::createObject(SettingsForm::class);
    $form->new_password = 'crafted-password';
    $form->current_password = 'qwerty';
    $I->assertFalse($form->save());
    $I->assertSame($message, $form->getFirstError('new_password'));
    $I->seeRecord(User::className(), ['id' => $user->id, 'password_hash' => $passwordHash]);

    $I->amGoingTo('check that the other account fields can still be saved');
    $I->amOnRoute('/user/settings/account');
    $I->fillField('#settingsform-username', 'renamed_user');
    $I->fillField('#settingsform-current_password', 'qwerty');
    $I->click('Save');
    $I->seeRecord(User::className(), ['id' => $user->id, 'username' => 'renamed_user', 'password_hash' => $passwordHash]);
} finally {
    Event::off(SettingsForm::class, SettingsForm::EVENT_PASSWORD_CHANGE_ALLOWED, $handler);
}
