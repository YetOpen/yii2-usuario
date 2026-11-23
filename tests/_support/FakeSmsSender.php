<?php

use yetopen\smssender\SmsSenderInterface;
use yii\base\Component;

/**
 * SMS sender for the tests: sends nothing, keeps the last number and message.
 */
class FakeSmsSender extends Component implements SmsSenderInterface
{
    public $lastNumber;
    public $lastMessage;

    /**
     * Makes the user module send its 2FA text messages through a new FakeSmsSender.
     *
     * @return self
     */
    public static function install()
    {
        $sender = new self();
        $module = Yii::$app->getModule('user');
        $validators = $module->twoFactorAuthenticationValidators;
        $validators['sms']['smsSender'] = $sender;
        $module->twoFactorAuthenticationValidators = $validators;

        return $sender;
    }

    public function getMinTextLength()
    {
        return 1;
    }

    public function getMaxTextLength()
    {
        return 160;
    }

    public function send($number, $message, $sender = null, $prefix = null, $delivery_time = null)
    {
        $this->lastNumber = $number;
        $this->lastMessage = $message;

        return true;
    }
}
