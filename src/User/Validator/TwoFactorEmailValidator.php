<?php

/*
 * This file is part of the 2amigos/yii2-usuario project.
 *
 * (c) 2amigOS! <http://2amigos.us/>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace Da\User\Validator;

use Da\TwoFA\Exception\InvalidSecretKeyException;
use Da\User\Model\User;
use Da\User\Service\TwoFactorEmailCodeGeneratorService;
use Da\User\Traits\ContainerAwareTrait;
use Yii;
use yii\helpers\ArrayHelper;

class TwoFactorEmailValidator extends TwoFactorCodeValidator
{
    use ContainerAwareTrait;

    protected $user;
    protected $code;
    protected $cycles;
    protected $type;

    /**
     * TwoFactorCodeValidator constructor.
     *
     * @param User   $user
     * @param string $code
     * @param int    $cycles
     */
    public function __construct(User $user, $code, $cycles = 0)
    {
        $this->user = $user;
        $this->code = $code;
        $this->cycles = $cycles;
        $this->type = 'email';
    }

    /**
     * @throws InvalidSecretKeyException
     * @return bool|int
     *
     */
    public function validate()
    {
        if (is_null($this->code) || $this->code == '') {
            return false;
        }
        // The code in the session is only valid for the user it was sent to.
        $codeUserId = Yii::$app->session->get(TwoFactorEmailCodeGeneratorService::SESSION_USER_ID);
        if ($codeUserId === null || (string) $codeUserId !== (string) $this->user->id) {
            return false;
        }
        $emailCodeTime = new \DateTime(Yii::$app->session->get(TwoFactorEmailCodeGeneratorService::SESSION_CODE_TIME));
        $currentTime = new \DateTime('now');
        $interval = $currentTime->getTimestamp() - $emailCodeTime->getTimestamp();

        $module = Yii::$app->getModule('user');
        $validators = $module->twoFactorAuthenticationValidators;
        $codeDurationTime = ArrayHelper::getValue($validators, $this->type.'.codeDurationTime', 300);

        if ($interval > $codeDurationTime) {
            return false;
        }
        $emailCode = Yii::$app->session->get(TwoFactorEmailCodeGeneratorService::SESSION_CODE);
        return $emailCode !== null && hash_equals((string) $emailCode, (string) $this->code);
    }

    /**
     * Spends the code sent by e-mail: called once it has been used successfully.
     */
    public function clearCode()
    {
        Yii::$app->session->remove(TwoFactorEmailCodeGeneratorService::SESSION_CODE);
        Yii::$app->session->remove(TwoFactorEmailCodeGeneratorService::SESSION_CODE_TIME);
        Yii::$app->session->remove(TwoFactorEmailCodeGeneratorService::SESSION_USER_ID);
    }

    /**
     * @return bool
     *
     */
    public function isValidationCodeToBeSent()
    {
        return true;
    }

    /**
     * @return string
     *
     */
    public function getSuccessMessage()
    {
        return Yii::t('usuario', 'Two factor authentication successfully enabled.');
    }

    /**
     *
     * @param  mixed  $codeDurationTime
     * @return string
     */
    public function getUnsuccessMessage($codeDurationTime)
    {
        return Yii::t('usuario', 'Please, enter the right code. The code is valid for {0} seconds. If you want to get a new code, please close this window and repeat the enabling request.', [$codeDurationTime]);
    }

    /**
    *
    * @param mixed $codeDurationTime
    * @return string
    */
    public function getUnsuccessLoginMessage($codeDurationTime)
    {
        return Yii::t('usuario', 'Please, enter the right code. The code is valid for {0} seconds. If you want to get a new code, please click on \'Cancel\' and repeat the login request.', [$codeDurationTime]);
    }

    /**
    * @return string
    *
    */
    public function generateCode()
    {
        return $this->make(TwoFactorEmailCodeGeneratorService::class, [$this->user])->run();
    }
}
