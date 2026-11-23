<?php

/*
 * This file is part of the 2amigos/yii2-usuario project.
 *
 * (c) 2amigOS! <http://2amigos.us/>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace Da\User\Service;

use Da\TwoFA\Manager;
use Da\User\Contracts\ServiceInterface;
use Da\User\Factory\MailFactory;
use Da\User\Model\User;
use Yii;

class TwoFactorEmailCodeGeneratorService implements ServiceInterface
{
    /**
     * Session keys holding the last code sent, when it was sent and the id of the user it
     * was sent to: a code is only valid for that user (see TwoFactorEmailValidator).
     */
    const SESSION_CODE = 'email_code';
    const SESSION_CODE_TIME = 'email_code_time';
    const SESSION_USER_ID = 'email_code_user_id';

    /**
     * @var User
     */
    protected $user;

    /**
     * TwoFactorEmailCodeGeneratorService constructor.
     *
     * @param User $user
     */
    public function __construct(User $user)
    {
        $this->user = $user;
    }

    /**
     * @inheritdoc
     */
    public function run()
    {
        $user = $this->user;
        if (!$user->auth_tf_key) {
            $user->auth_tf_key = (new Manager())->generateSecretKey();
            $user->updateAttributes(['auth_tf_key']);
        }
        // generate key
        $code = random_int(0, 999999);
        $code = str_pad($code, 6, 0, STR_PAD_LEFT);
        // send email
        $mailService = MailFactory::makeTwoFactorCodeMailerService($user, $code);
        // check the sending emailYii::t(
        if (!$mailService->run()) {
            Yii::$app->session->addFlash('error', Yii::t('usuario', 'The email sending failed, please check your configuration.'));
            return false;
        }
        // put key in session
        Yii::$app->session->set(self::SESSION_CODE_TIME, date('Y-m-d H:i:s'));
        Yii::$app->session->set(self::SESSION_CODE, $code);
        Yii::$app->session->set(self::SESSION_USER_ID, $user->id);

        return $code;
    }
}
